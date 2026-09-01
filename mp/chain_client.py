"""
chain_client.py — Blockchain, encryption, and cloud-storage operations
used by SecureShare's Data Owner and User roles.

This module connects SecureShare to:
- Ethereum/Infura for on-chain metadata and access-control operations.
- Google Drive for encrypted file/chunk storage.
- AES for encrypting and decrypting file chunks.
- The access polynomial for securely deriving a file key for users
  who currently have access.

Data is stored as encrypted chunks in Google Drive, while file metadata,
access requests, ownership, and access-control information are maintained
on the blockchain.
"""


import hashlib
import secrets
import json
import os
import io
import time
import tempfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import keccak, SHA256
from Crypto.Random import get_random_bytes
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.http import MediaIoBaseDownload
from web3 import Web3
from decouple import config


# -------------------- CONFIGURATION & BLOCKCHAIN CONNECTION --------------------

# Sensitive configuration is loaded from environment variables / .env.
BLOCKCHAIN_URL = config('INFURA_SEPOLIA_URL')
CONTRACT_ABI_PATH = config('CONTRACT_ABI_PATH', default='AccessControlABI.json')
CONTRACT_ADDRESS = config('CONTRACT_ADDRESS')
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDS_FILE = config('GOOGLE_CREDS_FILE', default='credentials.json')

# Create the Web3 connection used throughout this module.
w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))


# ---------------------------------------------------------------------
# BLOCKCHAIN / RPC HELPERS
# ---------------------------------------------------------------------

def _retry_on_429(fn, retries=3, base_delay=2):
    """
    Retry an RPC operation when the provider responds with HTTP 429.

    Infura's free tier can temporarily reject requests when its rate limit
    is reached, so read and write operations use exponential backoff.
    """
    for attempt in range(retries):
        try:
            return fn()
        except Exception as e:
            is_429 = '429' in str(e) or 'Too Many Requests' in str(e)
            if not is_429 or attempt == retries - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))


def _raw_tx_bytes(signed_tx):
    """
    Return the raw signed transaction bytes across supported web3.py versions.

    web3.py has used both raw_transaction and rawTransaction depending
    on the installed version.
    """
    for attr in ('raw_transaction', 'rawTransaction'):
        if hasattr(signed_tx, attr):
            return getattr(signed_tx, attr)
    raise AttributeError(
        "SignedTransaction has neither 'raw_transaction' nor 'rawTransaction' — "
        "unexpected web3.py version, check `pip show web3`."
    )

# Fail immediately if the blockchain connection cannot be established.
if not w3.is_connected():
    raise Exception("Failed to connect to Ethereum network!")

# Load the deployed contract's ABI so Python can interact with its methods.
with open(CONTRACT_ABI_PATH, "r") as abi_file:
    CONTRACT_ABI = json.load(abi_file)


# ---------------------------------------------------------------------
# GOOGLE DRIVE OPERATIONS
# ---------------------------------------------------------------------
"""
    Authenticate the current user with Google Drive and return a Drive service.
    A fresh local authentication token is used for each operation so that
"""
def authenticate_google_drive():
    if os.path.exists('token.json'):
        os.remove('token.json')
    flow = InstalledAppFlow.from_client_secrets_file(CREDS_FILE, SCOPES)
    creds = flow.run_local_server(
        port=0,
        success_message=(
            'Authentication complete. You can close this tab now and '
            'return to the SecureShare tab — your upload/download is '
            'still in progress there, do not close or refresh it.'
        ),
    )
    return build('drive', 'v3', credentials=creds)

"""Upload an encrypted file/chunk to Google Drive and return its sharing URL."""
def upload_file_to_drive(file_path, service):
    file_metadata = {'name': os.path.basename(file_path)}
    media = MediaIoBaseUpload(io.FileIO(file_path, 'rb'), mimetype='application/octet-stream')
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    drive_id = file['id']
    return f"https://drive.google.com/file/d/{drive_id}/view?usp=sharing"

def create_new_file(file_path):
    with open(file_path, 'wb') as f:
        f.write(b'')
    return file_path


# ---------------------------------------------------------------------
# HASHING & FILE CHUNKING
# ---------------------------------------------------------------------

def sha256_hash(data):
    """Compute the SHA256 hash of the given bytes."""
    return hashlib.sha256(data).digest()


def chunk_file(file_path):
    """Return the list of chunk hashes for a file (128KB chunks)."""
    chunk_size = 128 * 1024
    file_hashes = []
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            file_hashes.append(sha256_hash(chunk))
    return file_hashes


def chunker(file_path, chunks_to_upload, master_key, nonce):
    """Encrypt+upload only the chunks listed in chunks_to_upload; 
       Returns Drive links keyed by hash."""
    chunk_size = 128 * 1024
    links = {}
    i = 0
    service = authenticate_google_drive()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h = sha256_hash(chunk)
            if h in chunks_to_upload:
                enc_chunk = encrypt_file(chunk, master_key, nonce)
                fd, enc_chunk_file = tempfile.mkstemp(suffix=".enc")
                os.close(fd)
                
                with open(enc_chunk_file, 'wb') as enc_file:
                    enc_file.write(enc_chunk)
                chunk_link = upload_file_to_drive(enc_chunk_file, service)
                links[h] = chunk_link
                os.remove(enc_chunk_file)
                i += 1
    return links


# ---------------------------------------------------------------------
# ENCRYPTION, DECRYPTION, AND ACCESS-POLYNOMIAL MATH
# ---------------------------------------------------------------------

def encrypt_file(chunk, key, nonce):
    """Encrypt one file chunk using AES-CBC."""
    cipher = AES.new(key, AES.MODE_CBC, iv=nonce)
    return cipher.encrypt(pad(chunk, AES.block_size))

def decrypt_file(ciphertext, key, iv):
    """Decrypt one AES-CBC encrypted chunk and remove its padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# Fixed field prime used by the access polynomial.
#
# It must remain identical across all application processes because
# polynomial coefficients published by one process are evaluated by
# another process later. It is also larger than 2**256 so that a
# 32-byte AES key can be represented without losing information.
_POLY_FIELD_PRIME = 20492744823299702534257502703885914037193712748375587806734741775699946731807453
# 264-bit field elements require exactly 33 bytes for lossless storage.
_POLY_COEFF_BYTES = 33
# Fresh nonce used by the access polynomial on every publish operation.
_POLY_R_BYTES = 16

# -------------------- ACCESS-POLYNOMIAL FUNCTIONS --------------------

# Produce h(Ki, r), binding a user's subscription key to the polynomial's current random nonce.
def _poly_hash(key_bytes, r):
    digest = SHA256.new(key_bytes + r).digest()
    return int.from_bytes(digest, 'big') % _POLY_FIELD_PRIME


"""
    Derive the file's AES key from owner-controlled secrets.

    The resulting key is never stored directly on-chain. The public file
    tag and salt are combined with the owner's private key to deterministically
    recreate the same AES key whenever the owner needs it.
"""
def derive_cipher_key(private_key, file_tag, key_salt):
    pk_hex = private_key[2:] if private_key.startswith('0x') else private_key
    return sha256_hash(bytes.fromhex(pk_hex) + file_tag + key_salt + b"secure_share_cipher_key_v1")

"""
    Build the access polynomial used to derive the file key for
    currently-authorized users.

    Each user's subscription key becomes a root of the polynomial.
    The master AES key is encoded in the constant term.
"""
def compute_access_polynomial_coefficients(user_keys, master_key, r):
    """     
    user_keys: list of each currently-granted user's subs_key (bytes).
    master_key: the file's AES cipher-key (32 bytes).
    r: fresh random nonce (bytes, _POLY_R_BYTES long) for this publish.
    """
    if not user_keys:
        raise ValueError("Error: user_keys list is empty!")

    master_key_int = int.from_bytes(master_key, byteorder='big')
    if master_key_int >= _POLY_FIELD_PRIME:
        raise ValueError("cipher_key does not fit in the polynomial field.")

    n = len(user_keys)

    # The extra slot stores the implicit monic leading coefficient.
    coeff = [0] * (n + 1)
    coeff[0] = (-_poly_hash(user_keys[0], r)) % _POLY_FIELD_PRIME
    coeff[1] = 1                                                    

    for i in range(2, n + 1):  
        beta = _poly_hash(user_keys[i - 1], r) 
        coeff[i] = 1  # step 6
        for j in range(i - 1, 0, -1):  # step 7
            coeff[j] = (coeff[j - 1] - beta * coeff[j]) % _POLY_FIELD_PRIME
        coeff[0] = (-beta * coeff[0]) % _POLY_FIELD_PRIME

    coeff[0] = (coeff[0] + master_key_int) % _POLY_FIELD_PRIME
      # The leading coefficient is always 1 and is reconstructed during evaluation.
    return coeff[:n]


def evaluate_access_polynomial(coefficients, subs_key, r):
    """
    Evaluate the published polynomial using a user's subscription key.

    A currently-authorized user's subscription key is a polynomial root,
    allowing the original AES key to be recovered.
    """
    x = _poly_hash(subs_key, r)
    n = len(coefficients)
    s = coefficients[0] if n else 0
    y = 1
    for i in range(1, n):
        y = (y * x) % _POLY_FIELD_PRIME
        s = (s + coefficients[i] * y) % _POLY_FIELD_PRIME
    # Re-add the implicit monic leading coefficient.
    y = (y * x) % _POLY_FIELD_PRIME
    s = (s + y) % _POLY_FIELD_PRIME
    return s


def derive_cipher_key_from_polynomial(coefficients, subs_key, r):
    """
    Recover the 32-byte AES key by evaluating the access polynomial.

    A subscription key belonging to a revoked or unauthorized user is
    not a root of the current polynomial and therefore does not recover
    the correct encryption key.
    """
    value = evaluate_access_polynomial(coefficients, subs_key, r)
    return value.to_bytes(32, 'big')


# -------------------- POLYNOMIAL METADATA SERIALIZATION --------------------

def _pack_keyinfo(r, coefficients):
    """
    Pack the polynomial nonce and coefficients into the contract's single coefficients bytes field.
    The nonce is stored first, followed by fixed-width coefficients.
    """
    if len(r) != _POLY_R_BYTES:
        raise ValueError(f"r must be exactly {_POLY_R_BYTES} bytes")
    parts = [r]
    for c in coefficients:
        parts.append(int(c).to_bytes(_POLY_COEFF_BYTES, 'big'))
    return b''.join(parts)


def _unpack_keyinfo(blob):
    """
    Extract the nonce and polynomial coefficients from on-chain metadata.
    Returns (None, []) when no polynomial has been published yet.
    """
    if not blob or len(blob) < _POLY_R_BYTES:
        return None, []
    r = blob[:_POLY_R_BYTES]
    rest = blob[_POLY_R_BYTES:]
    if len(rest) % _POLY_COEFF_BYTES != 0:
        raise ValueError(
            "Corrupt KeyInfo metadata: coefficient section is not a "
            "multiple of the fixed coefficient width. This file's "
            "polynomial may have been published by an older, "
            "incompatible version of this code — try granting or "
            "revoking access again to republish it."
        )
    coefficients = [
        int.from_bytes(rest[i:i + _POLY_COEFF_BYTES], 'big')
        for i in range(0, len(rest), _POLY_COEFF_BYTES)
    ]
    return r, coefficients


# ---------------------------------------------------------------------
# Registration / Login
# ---------------------------------------------------------------------
class UserAlreadyRegisteredError(Exception):
    """Raised when the requested username already exists on-chain."""
    def __init__(self, username):
        self.username = username
        super().__init__(f'"{username}" is already registered on-chain.')


def _user_exists_on_chain(contract, username):
    """
    Check whether a username already has a user record on-chain.
    The contract returns a zero-value tuple instead of necessarily reverting
    when a username does not exist, so the returned username field is checked.
    """
    try:
        existing = _retry_on_429(lambda: contract.functions.getUser(username).call())
    except Exception:
        # A revert here means "not found" on some ABI versions — treat as absent.
        return False
    return bool(existing) and len(existing) > 1 and existing[1] == username



def register_user(username, password, name, email, department, subscription_period, private_key):
    """Register a new SecureShare user on the blockchain."""

    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    address = w3.eth.account.from_key(private_key).address

    # Check for duplicates before spending gas on a transaction.
    if _user_exists_on_chain(contract, username):
        raise UserAlreadyRegisteredError(username)

    register_user_data = {
        "username": username,
        "password": password,
        "name": name,
        "email": email,
        "department": department,
        "subscriptionPeriod": subscription_period
    }

    tx = contract.functions.registerUser(register_user_data).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address, 'pending')
    })
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
    txn_hash = w3.eth.send_raw_transaction(_raw_tx_bytes(signed_tx))
    receipt = w3.eth.wait_for_transaction_receipt(txn_hash)

    # A mined transaction can still have status 0 if the contract reverted.
    if receipt.status != 1:
        raise Exception(
            f'registerUser transaction reverted on-chain for "{username}" '
            f'(tx {txn_hash.hex()}). This is NOT a duplicate-user error — '
            f'check the transaction on Etherscan for the revert reason.'
        )

    user_id = _retry_on_429(lambda: contract.functions.getUser(username).call())[0]
    return user_id



def login_user(username, password, private_key):
    """Validate a user's blockchain-stored password and return their user data."""

    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    user_data = _retry_on_429(lambda: contract.functions.getUser(username).call())

    if user_data[1] != username:
        return None, None

    # Passwords are compared using the same Keccak-256 representation
    # used when the user record was created.
    keccak256 = keccak.new(digest_bits=256)
    keccak256.update(password.encode())
    password_hash = keccak256.digest()

    if user_data[2] == password_hash:
        return user_data, private_key
    return None, None


# ---------------------------------------------------------------------
# DATA OWNER
# ---------------------------------------------------------------------
"""
    Provides file-owner operations such as uploading, granting access,
    revoking access, deleting, and downloading owned files.
"""
class DataOwner:
    def __init__(self, private_key, contract_address=CONTRACT_ADDRESS):
        self.private_key = private_key
        self.address = w3.eth.account.from_key(private_key).address
        self.contract = w3.eth.contract(address=contract_address, abi=CONTRACT_ABI)
        self._next_nonce = None  # fetched once, then tracked locally — see _send()

# -------------------- SEND TRANSACTION TO BLOCKCHAIN --------------------
    def _send(self, function_call):
        """
        Build, sign, send, and verify a blockchain transaction.

        The local nonce counter avoids repeatedly querying the RPC provider
        immediately after previous transactions have been mined.
        """
        if self._next_nonce is None:
            self._next_nonce = _retry_on_429(lambda: w3.eth.get_transaction_count(self.address, 'pending'))

        nonce = self._next_nonce
        tx = function_call.build_transaction({
            'from': self.address,
            'nonce': nonce,
        })
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
        txn_hash = _retry_on_429(lambda: w3.eth.send_raw_transaction(_raw_tx_bytes(signed_tx)))
        receipt = _retry_on_429(lambda: w3.eth.wait_for_transaction_receipt(txn_hash))
        self._next_nonce = nonce + 1

        # A receipt with status 0 means the transaction was mined but reverted.
        if receipt.status != 1:
            raise Exception(
                f'Transaction reverted on-chain (tx {txn_hash.hex()}). '
                f'Check the transaction on Etherscan for the revert reason.'
            )
        return receipt


# -------------------- FILE OPERATIONS --------------------

    def upload_file(self, file_path, access_policy):
        """
        Upload a file in encrypted chunks and store its metadata on-chain.
        Returns:
          1 -> File already exists;existing file metadata was updated
          2 -> reserved for filename/content collision handling
          3 -> new file was uploaded
        """
        file_name = os.path.basename(file_path)
        file_tag = sha256_hash(file_name.encode())
        chunk_hashes = chunk_file(file_path)
        nonce = get_random_bytes(16)

        existing_metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        file_exists = bool(existing_metadata[0])  # fileLink non-empty => exists

        if file_exists:
            # Reuse the existing public salt so the existing encrypted
            # content does not need to be replaced just to update metadata.
            key_salt = existing_metadata[3]
            cipher_key = derive_cipher_key(self.private_key, file_tag, key_salt)
            existing_chunk_hashes = set(existing_metadata[0])
            chunks_to_upload = [c for c in chunk_hashes if c not in existing_chunk_hashes]

            # Upload only chunks that are not already registered.
            if chunks_to_upload:
                new_links = chunker(file_path, chunks_to_upload, cipher_key, nonce)
                for chunk_hash, link in new_links.items():
                    self._send(self.contract.functions.uploadChunkMetadata(
                        chunk_hash, {"chunkLink": link}
                    ))

            owners = list(existing_metadata[1])
            if self.address not in owners:
                owners.append(self.address)

            access_policies = list(existing_metadata[4])
            access_policies.append(access_policy)

            updated_metadata = {
                "fileLink": chunk_hashes,
                "uploaders": owners,
                "iv": existing_metadata[2],
                "cipherKey": key_salt,
                "accessPolicy": access_policies,
                "coefficients": existing_metadata[5],
                "request_id": list(existing_metadata[6]),
            }
            self._send(self.contract.functions.uploadFileMetadata(file_tag, updated_metadata))
            return (1, "")

        # -------------------- A new file receives a fresh public salt and AES key --------------------
        key_salt = get_random_bytes(16)
        cipher_key = derive_cipher_key(self.private_key, file_tag, key_salt)

        links = chunker(file_path, set(chunk_hashes), cipher_key, nonce)
        for chunk_hash, link in links.items():
            self._send(self.contract.functions.uploadChunkMetadata(
                chunk_hash, {"chunkLink": link}
            ))

        # No access polynomial exists until the first user is granted access.
        file_metadata = {
            "fileLink": chunk_hashes,
            "uploaders": [self.address],
            "iv": nonce,
            "cipherKey": key_salt,
            "accessPolicy": [access_policy],
            "coefficients": b"",
            "request_id": [],
        }
        self._send(self.contract.functions.uploadFileMetadata(file_tag, file_metadata))
        return (3, "")

# ---------------------------------------------------------------------
#  ACCESS CONTROL 
# ---------------------------------------------------------------------

    def get_pending_requests(self, file_name):
        """
        Return access requests currently associated with an owner's file.

        Access-policy evaluation is handled by the Django application,
        not by this blockchain client.
        """
        file_tag = sha256_hash(file_name.encode())
        metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        if not metadata[0]:
            return "File Not Found"

        uploaders = metadata[1]
        if self.address not in uploaders:
            return "File Not Found"

        request_ids = metadata[6]
        results = []
        for req_id in request_ids:
            req_bytes = _retry_on_429(lambda: self.contract.functions.getRequest(req_id).call())
            try:
                parts = req_bytes.decode().split('\\')
                req_filename, username = parts[0], parts[1]
            except Exception:
                continue
            if req_filename != file_name:
                continue
            results.append({"request_id": req_id, "username": username})
        return results


    def get_access_policy(self, file_name):
        """Returns this owner's access-policy string ('key:value, key:value') for a file."""
        file_tag = sha256_hash(file_name.encode())
        metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        if not metadata[0]:
            return None
        uploaders = metadata[1]
        access_policies = metadata[4]
        if self.address not in uploaders:
            return None
        return access_policies[uploaders.index(self.address)]


# -------------------- GRANT / REVOKE ACCESS --------------------

    def grant_access(self, file_name, details, owner_username):
        """
        Grant or deny pending access requests.

        The caller supplies the result of the access-policy check.
        Approved users receive a new subscription key that is later used
        as a root of the file's access polynomial.
        """
        file_tag = sha256_hash(file_name.encode())
        metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        if not metadata[0]:
            raise ValueError("File not found")

        granted = []

        for entry in details:
            if entry["satisfies_policy"]:
                subs_key = secrets.token_bytes(16)
                res_str = file_name + "\\" + subs_key.hex() + "\\" + self.address
                self._send(self.contract.functions.grantAccess(
                    entry["request_id"], res_str.encode(), 1
                ))
                granted.append((entry["username"], subs_key.hex()))
            else:
                self._send(self.contract.functions.grantAccess(
                    entry["request_id"], b"", 2
                ))

        return granted


    def recompute_and_publish_coefficients(self, file_name, all_user_keys_hex):
        """
        Rebuild and publish the access polynomial after an access change.

        A fresh random nonce is generated every time the polynomial is
        published so that previously published polynomial values cannot
        simply be reused after a grant/revoke operation.
        """
        file_tag = sha256_hash(file_name.encode())
        metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        key_salt = metadata[3]
        cipher_key = derive_cipher_key(self.private_key, file_tag, key_salt)

        user_keys = [bytes.fromhex(k) for k in all_user_keys_hex]
        r_new = secrets.token_bytes(_POLY_R_BYTES)
        coeffs = compute_access_polynomial_coefficients(user_keys, cipher_key, r_new)
        packed = _pack_keyinfo(r_new, coeffs)

        self._send(self.contract.functions.updateFileMetadata(file_tag, packed))


    def display_users(self, file_name, owner_username):
        """
        Placeholder for retrieving currently granted users.

        The deployed contract does not provide a queryable list of all
        currently granted users, so the Django Subscription model is the
        authoritative source for this information.
        """
        raise NotImplementedError(
            "display_users should be implemented in views.py using the "
            "Subscription model (file, user_id -> user_names) since the "
            "contract does not track a queryable 'granted users' list."
        )


    def revoke_access(self, file_name, remaining_user_keys_hex, revoked_request_ids):
        """
        - Revoke access by re-encrypting the file with a new AES key.
        - The file is downloaded, decrypted with the old key, encrypted again
        with a new key, and uploaded as new encrypted chunks. A new access
        polynomial is then created for users who should retain access.
        - The contract's revokeAccess() is also used to clear the revoked
        request responses and provide an on-chain revocation event.
        """
        file_tag = sha256_hash(file_name.encode())
        metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        if not metadata[0]:
            raise ValueError("File not found")

        old_key_salt = metadata[3]
        old_cipher_key = derive_cipher_key(self.private_key, file_tag, old_key_salt)
        old_iv = metadata[2]
        chunk_hashes = metadata[0]

        # Download and decrypt the existing chunks before re-encryption.
        ''' Get the File from Drive '''
        service = authenticate_google_drive()
        plaintext_chunks = []
        old_drive_ids = []
        for chunk_hash in chunk_hashes:
            chunk_metadata = _retry_on_429(lambda: self.contract.functions.getChunkMetadata(chunk_hash).call())
            if not chunk_metadata[0]:
                continue
            drive_id = chunk_metadata[0][32:].split('/')[0]
            old_drive_ids.append(drive_id)

            fd, local_enc = tempfile.mkstemp(suffix=".enc")
            os.close(fd)
            request = service.files().get_media(fileId=drive_id)
            fh = io.FileIO(local_enc, 'wb')
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
            fh.close()

            with open(local_enc, "rb") as f:
                encrypted_data = f.read()
            os.remove(local_enc)
            plaintext_chunks.append(decrypt_file(encrypted_data, old_cipher_key, old_iv))


        # Generate a completely new encryption key and IV.
        new_key_salt = get_random_bytes(16)
        new_cipher_key = derive_cipher_key(self.private_key, file_tag, new_key_salt)
        new_nonce = get_random_bytes(16)

        # Reconstruct the plaintext temporarily so it can be chunked and
        # encrypted again using the new key.
        with tempfile.TemporaryDirectory() as tmp_dir:
            local_path = os.path.join(tmp_dir, file_name)
            with open(local_path, 'wb') as f:
                for chunk in plaintext_chunks:
                    f.write(chunk)

            chunk_hashes_new = chunk_file(local_path)
            new_links = chunker(local_path, set(chunk_hashes_new), new_cipher_key, new_nonce)
            for chunk_hash, link in new_links.items():
                self._send(self.contract.functions.uploadChunkMetadata(chunk_hash, {"chunkLink": link}))
      
        # Publish a polynomial only when at least one user retains access.
        if remaining_user_keys_hex:
            user_keys = [bytes.fromhex(k) for k in remaining_user_keys_hex]
            r_new = secrets.token_bytes(_POLY_R_BYTES)
            coeffs = compute_access_polynomial_coefficients(user_keys, new_cipher_key, r_new)
            coefficients = _pack_keyinfo(r_new, coeffs)
        else:
            coefficients = b""  # no one left with access

        updated_metadata = {
            "fileLink": chunk_hashes_new,
            "uploaders": list(metadata[1]),
            "iv": new_nonce,
            "cipherKey": new_key_salt,
            "accessPolicy": list(metadata[4]),
            "coefficients": coefficients,
            "request_id": list(metadata[6]),
        }

        if not revoked_request_ids:
            raise ValueError("revoke_access() requires at least one revoked_request_ids entry")

        # Revoke each affected request on-chain.
        for req_id_hex in revoked_request_ids:
            req_id_hex = req_id_hex[2:] if req_id_hex.startswith('0x') else req_id_hex
            req_id_bytes = bytes.fromhex(req_id_hex)
            self._send(self.contract.functions.revokeAccess(req_id_bytes, file_tag, updated_metadata))

        # Remove old encrypted Drive objects only after the new metadata
        # has been successfully published on-chain.
        for old_id in old_drive_ids:
            try:
                service.files().delete(fileId=old_id).execute()
            except Exception:
                pass    


# --------------- DELETE FILE ------------------
    def delete_file(self, file_name, revoked_request_ids=None):
        """
        Remove a file from SecureShare.

        The deployed contract has no dedicated delete function, so deletion
        is represented by clearing the file metadata. Encrypted chunks are
        also removed from Google Drive on a best-effort basis.
        """        

        file_tag = sha256_hash(file_name.encode())
        metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        if not metadata[0]:
            raise ValueError("File not found")
        if self.address not in metadata[1]:
            raise ValueError("Not authorized: you are not an owner of this file")

        # Delete the encrypted chunk objects from cloud storage.
        chunk_hashes = metadata[0]
        service = authenticate_google_drive()
        for chunk_hash in chunk_hashes:
            chunk_metadata = _retry_on_429(lambda: self.contract.functions.getChunkMetadata(chunk_hash).call())
            if not chunk_metadata[0]:
                continue
            drive_id = chunk_metadata[0][32:].split('/')[0]
            try:
                service.files().delete(fileId=drive_id).execute()
            except Exception:
                pass

        # Clear the on-chain metadata to represent deletion.
        cleared_metadata = {
            "fileLink": [],
            "uploaders": [],
            "iv": get_random_bytes(16),
            "cipherKey": get_random_bytes(16),
            "accessPolicy": [],
            "coefficients": b"",
            "request_id": [],
        }

        revoked_request_ids = revoked_request_ids or []
        # Revoke existing requests so their old subscription cannot be used.
        if revoked_request_ids:
            for req_id_hex in revoked_request_ids:
                req_id_hex = req_id_hex[2:] if req_id_hex.startswith('0x') else req_id_hex
                req_id_bytes = bytes.fromhex(req_id_hex)
                self._send(self.contract.functions.revokeAccess(req_id_bytes, file_tag, cleared_metadata))
        else:
        # With no existing approved requests, directly clear the metadata.
            self._send(self.contract.functions.uploadFileMetadata(file_tag, cleared_metadata))


    def owner_download_file(self, file_name):
        """
        Download and decrypt a file owned by the current user.

        Owners derive the AES key directly from their private key and the
        file's public salt, so they do not need the subscription-key /
        access-polynomial flow used by regular users.
        Returns:
          1  -> success, file saved to ~/Downloads
         -1  -> file not found
         -3  -> current address is not an owner
        """

        file_tag = sha256_hash(file_name.encode())
        metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        if not metadata[0]:
            return -1

        uploaders = metadata[1]
        if self.address not in uploaders:
            return -3

        key_salt = metadata[3]
        cipher_key = derive_cipher_key(self.private_key, file_tag, key_salt)
        iv = metadata[2]
        chunk_hashes = metadata[0]

        # Download and decrypt every chunk in its original order.
        service = authenticate_google_drive()
        downloaded_files = []
        for chunk_hash in chunk_hashes:
            chunk_metadata = _retry_on_429(lambda: self.contract.functions.getChunkMetadata(chunk_hash).call())
            if not chunk_metadata[0]:
                continue
            drive_id = chunk_metadata[0][32:].split('/')[0]

            fd, local_enc = tempfile.mkstemp(suffix=".enc")
            os.close(fd)
            request = service.files().get_media(fileId=drive_id)
            fh = io.FileIO(local_enc, 'wb')
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
            fh.close()

            with open(local_enc, "rb") as f:
                encrypted_data = f.read()
            os.remove(local_enc)
            downloaded_files.append(decrypt_file(encrypted_data, cipher_key, iv))

        # Reassemble the decrypted chunks in the user's Downloads folder.
        downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
        os.makedirs(downloads_path, exist_ok=True)
        merged_path = os.path.join(downloads_path, file_name)
        with open(merged_path, 'wb') as merged_file:
            for chunk_data in downloaded_files:
                merged_file.write(chunk_data)

        return 1



# ---------------------------------------------------------------------
# USER - FILE ACCESS REQUESTER
# ---------------------------------------------------------------------

class User:

    def __init__(self, private_key, contract_address=CONTRACT_ADDRESS):
        self.private_key = private_key
        self.address = w3.eth.account.from_key(private_key).address
        self.contract = w3.eth.contract(address=contract_address, abi=CONTRACT_ABI)
         # Track transaction nonces locally to avoid RPC synchronization issues.
        self._next_nonce = None

    """Build, sign, send, and verify a blockchain transaction."""
    def _send(self, function_call):
        if self._next_nonce is None:
            self._next_nonce = _retry_on_429(lambda: w3.eth.get_transaction_count(self.address, 'pending'))

        nonce = self._next_nonce
        tx = function_call.build_transaction({
            'from': self.address,
            'nonce': nonce,
        })
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
        txn_hash = _retry_on_429(lambda: w3.eth.send_raw_transaction(_raw_tx_bytes(signed_tx)))
        receipt = _retry_on_429(lambda: w3.eth.wait_for_transaction_receipt(txn_hash))
        self._next_nonce = nonce + 1

        if receipt.status != 1:
            raise Exception(
                f'Transaction reverted on-chain (tx {txn_hash.hex()}). '
                f'Check the transaction on Etherscan for the revert reason.'
            )
        return receipt

    """
    Submit an on-chain access request for a file.
    """
    def request_access(self, file_name, username):
        """
        Returns:
          (1, request_id) -> request submitted
          (-1, None)     -> file does not exist
        """
        file_tag = sha256_hash(file_name.encode())
        file_metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        if not file_metadata[0]:
            return (-1, None)

        req_str = file_name + "\\" + username + "\\" + str(secrets.token_hex(16))
        req = req_str.encode()
        request_id = sha256_hash(req)

        self._send(self.contract.functions.requestAccess(file_tag, request_id, req))
        return (1, request_id.hex())


    def download_and_decrypt_file(self, file_name, username):
        """
        Download a file after the user's access request has been approved.

        The AES key is derived exclusively through the current access
        polynomial using the user's subscription key. A revoked user therefore
        cannot recover the current encryption key.
        Returns:
          1  -> success
          0  -> request still pending
          2  -> access denied / invalid response
         -1  -> file not found
         -2  -> no request found for this user
        """
        file_tag = sha256_hash(file_name.encode())
        file_metadata = _retry_on_429(lambda: self.contract.functions.getFileMetadata(file_tag).call())
        if not file_metadata[0]:
            return -1

        # Find this user's most recent request for this file to get its request_id
        request_ids = file_metadata[6]
        my_request_id = None
        for req_id in request_ids:
            req_bytes = _retry_on_429(lambda: self.contract.functions.getRequest(req_id).call())
            try:
                parts = req_bytes.decode().split('\\')
                req_filename, req_username = parts[0], parts[1]
            except Exception:
                continue
            if req_filename == file_name and req_username == username:
                my_request_id = req_id

        if my_request_id is None:
            return -2

        # The response determines whether the request is still pending,
        # denied, or contains the user's subscription key.
        response = _retry_on_429(lambda: self.contract.functions.getResponse(my_request_id).call())
        if response == b'\x00':
            return 0
        if response == b'\x02':
            return 2

        try:
            parts = response.decode().split('\\')
            my_subs_key = bytes.fromhex(parts[1])
        except Exception:
            return 2

        iv = file_metadata[2]
        chunk_hashes = file_metadata[0]

        # Extract the current polynomial nonce and coefficients.
        r, coefficients = _unpack_keyinfo(file_metadata[5])
        if r is None or not coefficients:
            return 2

         # Derive the AES key from the user's subscription key.
        cipher_key = derive_cipher_key_from_polynomial(coefficients, my_subs_key, r)

        # Download and decrypt each encrypted chunk.
        service = authenticate_google_drive()
        downloaded_files = []
        for chunk_hash in chunk_hashes:
            chunk_metadata = _retry_on_429(lambda: self.contract.functions.getChunkMetadata(chunk_hash).call())
            if not chunk_metadata[0]:
                continue
            chunk_link = chunk_metadata[0]
            drive_id = chunk_link[32:].split('/')[0]

            fd, local_enc = tempfile.mkstemp(suffix=".enc")
            os.close(fd)
            request = service.files().get_media(fileId=drive_id)
            fh = io.FileIO(local_enc, 'wb')
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()

            # Close the file before reopening/removing it. This is required
            # on Windows because open handles can lock the temporary file.
            fh.close()

            with open(local_enc, "rb") as f:
                encrypted_data = f.read()
            os.remove(local_enc)

            plaintext_chunk = decrypt_file(encrypted_data, cipher_key, iv)
            downloaded_files.append(plaintext_chunk)

        # Reassemble the decrypted chunks in the user's Downloads folder.
        downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
        os.makedirs(downloads_path, exist_ok=True)
        merged_path = os.path.join(downloads_path, file_name)
        with open(merged_path, 'wb') as merged_file:
            for chunk_data in downloaded_files:
                merged_file.write(chunk_data)

        return 1