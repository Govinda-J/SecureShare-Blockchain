# SecureShare

**Attribute-Based Encrypted File Sharing, secured with Blockchain**

SecureShare lets people upload files that only *specific, qualified* people can ever open — not because a server "decided" to let them in, but because the rules for who qualifies are locked into a tamper-proof public ledger (a blockchain) that no single person, including the app's own admin, can quietly rewrite.

This README is written so that even if you've never touched blockchain, smart contracts, or Django before, you can still get this project running end-to-end.

---

## Table of Contents

1. [What This Project Actually Does](#1-what-this-project-actually-does)
2. [A Quick, Plain-English Primer on Blockchain](#2-a-quick-plain-english-primer-on-blockchain)
3. [What's a "Smart Contract"?](#3-whats-a-smart-contract)
4. [Why Put Any of This On-Chain?](#4-why-put-any-of-this-on-chain)
5. [How SecureShare Is Designed](#5-how-secureshare-is-designed)
6. [Tech Stack](#6-tech-stack)
7. [What You Need Before You Start](#7-what-you-need-before-you-start)
8. [Step-by-Step Setup](#8-step-by-step-setup)
9. [Running the App](#9-running-the-app)
10. [Using the App — A Walkthrough](#10-using-the-app--a-walkthrough)
11. [Project Structure](#11-project-structure)
12. [Troubleshooting](#12-troubleshooting)
13. [Security Notes & Limitations](#13-security-notes--limitations)
14. [Credits](#14-credits)

---

## 1. What This Project Actually Does

Imagine a company file server, but with one twist: instead of an IT admin manually deciding "let Alice see this HR file," the file itself carries a **rule** — like `department:HR` — and *only* people whose verified attributes match that rule can ever decrypt it. Nobody, not even the app's admin, can bypass that rule after the fact, because:

- The **rule** (access policy) and every **grant/reject/revoke decision** are recorded on a public blockchain — permanent and visible to everyone, so nothing can be secretly altered later.
- The **file itself** is AES-encrypted, split into chunks, and stored on Google Drive — no single stored piece is ever a readable file on its own.
- **Attributes** (like `department:HR` or `clearance:secret`) are assigned only by a trusted admin — never self-declared by the person requesting access — so someone can't just type "I'm HR" and get in.

In short: **encrypted storage + admin-verified identity + an unchangeable public rulebook.**

*(Add a screenshot here of the Dashboard page, showing the "Upload / Request Access / Request Attributes" action cards.)*

---

## 2. A Quick, Plain-English Primer on Blockchain

Think of a blockchain as a **shared notebook** that thousands of computers around the world keep an identical copy of.

- Every time someone writes something new in the notebook (a "transaction"), it gets bundled with other recent entries into a **block**.
- Each block is stamped with a fingerprint of the block before it — like a chain of wax seals. If anyone tried to sneak back and change an old entry, the fingerprint wouldn't match anymore, and everyone else's copy would immediately flag it as fake.
- Because thousands of independent computers ("nodes") hold copies and constantly check each other's work, no single person — not even the person who built the app — can quietly edit history.

This project uses **Ethereum**, specifically its free public test network called **Sepolia** (a practice version of Ethereum that uses fake, worthless ETH — so you can experiment without spending real money).

**Wallets, addresses, and private keys** — the three terms you'll see everywhere:
- A **wallet** is like a bank account for the blockchain.
- Your **address** (e.g. `0xAbC123...`) is like your account number — safe to share.
- Your **private key** is like your account's master password. Whoever holds it can sign transactions "as you." **Never share it, never commit it to GitHub, never paste it anywhere public.**

**MetaMask** is a free browser extension that manages a wallet for you and lets you sign transactions without typing your private key into random websites each time.

---

## 3. What's a "Smart Contract"?

A **smart contract** is a small program that lives permanently on the blockchain. Once it's deployed:

- Its code cannot be silently changed by anyone (including its creator) — only redeployed as a brand-new contract at a new address.
- Anyone can call its functions, and every call that changes data is itself a permanent, visible transaction.
- It runs exactly as written, every time, for everyone — there's no "special admin override" hidden inside unless the code explicitly has one.

In SecureShare, the smart contract (`newsol1.sol`, written in Solidity — Ethereum's programming language) is the **public rulebook**. It stores:

- Who registered, and when
- Which file has which access policy
- Every access request, grant, rejection, and revocation — permanently, as named events anyone can audit later

Django (this app) never has the power to fake "Alice was granted access" without that grant actually existing as a real, verifiable blockchain transaction.

*(Add a screenshot here of a transaction on [Sepolia Etherscan](https://sepolia.etherscan.io) showing one of your own `AccessGranted` events, to make this concrete for readers.)*

---

## 4. Why Put Any of This On-Chain?

Compared to a normal database-only system, putting the access-control decisions on a blockchain buys you:

| Property | Plain database | Blockchain-backed (this project) |
|---|---|---|
| Can the admin secretly edit "who was granted access" after the fact? | Yes, trivially (`UPDATE` statement) | No — every past grant/reject/revoke is a permanent, timestamped, publicly checkable record |
| Can you independently verify a claimed grant/reject decision ever happened? | Only if you trust the app's own logs | Yes — anyone can check the transaction directly on a public block explorer |
| Single point of failure for the audit trail? | The app's own database | No single computer holds the only copy |

The trade-off: blockchain transactions cost a small "gas" fee (free on the Sepolia test network) and take a few seconds to confirm — so this project intentionally keeps the *bulk file storage* off-chain (on Drive) and only puts the lightweight, security-critical *decisions* on-chain.

---

## 5. How SecureShare Is Designed

This project's access-control approach is based on ideas from the academic paper *"Secure cloud file sharing scheme using blockchain and attribute-based encryption"* by Almasian & Shafieinejad — specifically its approach of encoding "who currently has access" as the **roots of a mathematical polynomial**, so that adding or removing a user just means republishing a new polynomial, without re-encrypting the file for every remaining user individually.

**In plain terms, here's the full journey of a file:**

1. **Upload**: You pick a file and define an access policy (e.g. `department:HR, clearance:2`). SecureShare encrypts the file with AES, splits it into 128 KB chunks, uploads the encrypted chunks to your Google Drive, and records the chunk locations + policy on the smart contract.
2. **Attributes**: A regular user doesn't get to say "I'm HR" — they *request* the attribute, and only a **staff admin** (using Django's built-in admin system, no wallet needed) can approve and assign it. This is the part that keeps the whole system honest.
3. **Request access**: A user asks to access a file — recorded as an on-chain `AccessRequested` event.
4. **Grant / Reject**: The file's owner reviews pending requests. SecureShare automatically checks the requester's *admin-verified* attributes against the file's policy and shows whether they qualify. The owner approves or rejects — recorded on-chain as `AccessGranted` / `AccessRejected`.
5. **Key distribution via a polynomial**: Instead of encrypting the file separately for every approved user, the owner publishes one compact polynomial on-chain. Each approved user holds a personal secret ("subscription key"). Only a personal key that is a genuine root of the *currently published* polynomial can mathematically recover the real decryption key. Revoke someone, and a fresh polynomial (without their key as a root) makes their old key useless — without touching anyone else's key.
6. **Revoke / Delete**: Revoking a user (or deleting a file entirely) re-encrypts and republishes a fresh polynomial, and the smart contract clears that user's stored response so it can never be replayed later.
7. **Activity Log**: Every action (upload, request, grant, reject, revoke, attribute change, delete) is written to a local, fast activity log — mirroring the on-chain events but without needing slow blockchain re-scans every time you open a page.

*(Add a diagram here showing: User → Encrypt+Chunk → Google Drive, and Metadata+Policy → Smart Contract → Blockchain.)*

*(Add a screenshot here of the Upload page and the Grant Access page, showing the access-policy fields and the "Satisfies Policy: Yes/No" table.)*

---

## 6. Tech Stack

| Layer | Technology |
|---|---|
| Web framework | Django (Python) |
| Database (app-side data) | SQLite |
| Blockchain | Ethereum Sepolia testnet |
| Blockchain client library | web3.py |
| Smart contract language | Solidity |
| File encryption | AES (via PyCryptodome) |
| File storage | Google Drive API |
| Wallet | MetaMask |
| Frontend | Django templates, plain CSS/JS |

---

## 7. What You Need Before You Start

Before touching any code, set up these four things. Each is free.

### 7.1 A Google Account + Google Drive API access
You'll enable the Drive API on your own Google account and download a small `credentials.json` file that lets *your local copy* of this app upload/download files to *your own* Drive — nothing is shared with anyone else.

### 7.2 A MetaMask wallet
A free browser extension wallet, switched to the **Sepolia test network**.

### 7.3 Free Sepolia test ETH
"Test" money with no real value, used to pay tiny gas fees for blockchain transactions on the test network. Available free from public faucets.

### 7.4 A free Infura account (or similar)
Infura gives your app a way to actually talk to the Ethereum network, without you having to run your own full Ethereum node.

Detailed steps for all four are in the setup section below.

---

## 8. Step-by-Step Setup

### Step 1 — Clone the repo

```bash
git clone https://github.com/<your-username>/secure-share.git
cd secure-share
```

### Step 2 — Create and activate a virtual environment

```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Set up your `.env` file

```bash
cp .env.example .env
```

Leave it open — you'll fill in real values as you go through Steps 5–7 below.

### Step 5 — Create a MetaMask wallet & get test ETH

1. Install the [MetaMask](https://metamask.io) browser extension and create a new wallet. **Write down your seed phrase somewhere safe offline — never share it or type it into any website.**
2. In MetaMask, switch the network dropdown to **Sepolia** (enable "Show test networks" in Settings if it's hidden).
3. Copy your wallet's address (starts with `0x...`).
4. Go to a free Sepolia faucet (e.g. `sepoliafaucet.com` or `sepolia-faucet.pk910.de` — search "Sepolia faucet" if a link is down, faucet availability changes over time) and request free test ETH to your address. You only need a small amount — each action in this app costs a fraction of a cent equivalent in gas.
5. From MetaMask, export your account's **private key** (Account details → Show private key). This is what you'll enter when registering in the app — **never share this key with anyone, and never commit it to Git.**

### Step 6 — Set up Google Drive API access

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project (any name, e.g. "SecureShare").
3. In the search bar, find and enable the **Google Drive API**.
4. Go to **APIs & Services → OAuth consent screen**. Choose **External**, fill in an app name and your email, and save (you can leave it in "Testing" mode — add your own Google account as a test user).
5. Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
6. Choose **Desktop app** as the application type, give it a name, and click Create.
7. Download the generated JSON file, rename it to `credentials.json`, and place it in the project's root folder (same folder as `manage.py`).
8. In your `.env` file, confirm `GOOGLE_CREDS_FILE=credentials.json`.

*(The first time you upload or download a file through the app, a browser tab will pop up asking you to log into your Google account and approve access — this is normal and only touches files this app itself creates, thanks to the restricted `drive.file` permission scope.)*

### Step 7 — Get an Infura endpoint

1. Go to [infura.io](https://www.infura.io) and create a free account.
2. Create a new API key / project.
3. Select **Sepolia** as the network and copy the HTTPS endpoint URL (looks like `https://sepolia.infura.io/v3/xxxxxxxx`).
4. Paste it into your `.env` file as `INFURA_SEPOLIA_URL`.

### Step 8 — Set the contract address

The smart contract (`newsol1.sol`) needs to already be deployed to Sepolia for the app to talk to it.

- **Easiest option**: use the already-deployed shared contract address provided in `.env.example` / by the project owner — just paste it into `CONTRACT_ADDRESS` in your `.env`.
- **Advanced option**: deploy your own copy using [Remix IDE](https://remix.ethereum.org) (paste in `newsol1.sol`, compile, connect MetaMask, deploy to Sepolia) and use your own contract's address instead. If you deploy your own, also update `CONTRACT_DEPLOY_BLOCK` in `.env` to the block number your deployment transaction landed in (visible on Sepolia Etherscan) — this makes the Activity Log faster by not scanning from block zero.

### Step 9 — Fill in the remaining `.env` values

```
DJANGO_SECRET_KEY=<any long random string>
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost
```

### Step 10 — Run database migrations

```bash
python manage.py migrate
```

### Step 11 — Create an admin (staff) account

This is a separate concept from a normal registered user — it's Django's own built-in admin system, used only for verifying attributes and monitoring site-wide activity. It does **not** need a MetaMask wallet.

```bash
python manage.py createsuperuser
```

Follow the prompts to set a username, email, and password.

---

## 9. Running the App

```bash
python manage.py runserver
```

Open your browser to **http://127.0.0.1:8000/**

- Regular users register/login at the normal homepage.
- The admin logs in at **http://127.0.0.1:8000/admin/login/?next=/staff/** (also linked as "Staff Login" on the homepage) using the superuser credentials from Step 11.

*(Add a screenshot here of the homepage / login page.)*

---

## 10. Using the App — A Walkthrough

1. **Register** — create an account. You'll be asked for your MetaMask private key (from Step 5) — this registers your wallet address on-chain and links it to your app account.
2. **Request an attribute** — from your Dashboard, go to "Request Attributes" and ask for something like `department:HR`. This just creates a pending request; it does nothing on its own yet.
3. **Admin approves it** — log in as the staff admin at `/staff/`, find the pending attribute request, and approve it. Now your account genuinely has that attribute.
4. **Upload a file** — go to "Upload File," choose a file, and set an access policy such as `department:HR`. Only accounts with that exact admin-verified attribute will ever qualify.
5. **Another user requests access** — from their Dashboard, "File Access Request" → enter the filename.
6. **You grant or reject it** — go to "Files" → "Review Requests" on your uploaded file. SecureShare shows you whether the requester's verified attributes satisfy your policy, and you approve or reject with one click.
7. **They download it** — once approved, the requester sees the file under "Files You Can Access" and can download + decrypt it.
8. **Revoke or delete anytime** — as the owner, you can revoke a specific user's access (their old key stops working immediately) or delete the file entirely.
9. **Check the Activity Log** — every one of these actions is listed, both on your personal Activity page and (site-wide) on the admin dashboard.

*(Add screenshots here of: Files page, Grant Access page with the satisfaction table, and the Activity Log.)*

---

## 11. Project Structure

```
secure_share/
├── manage.py                # Django's command-line entry point
├── newsol1.sol               # The smart contract source code
├── newabi.json                # Compiled contract's interface (used by Python to call it)
├── requirements.txt
├── .env.example
├── secure_share/
│   ├── settings.py            # Django configuration
│   └── urls.py                 # Top-level URL routing
└── mp/                         # The main Django app
    ├── models.py                # Database tables (Profile, File, AccessRequest, etc.)
    ├── views.py                  # Page logic — what happens on each request
    ├── new1.py                    # All blockchain + encryption + Drive logic
    ├── attributes.py               # Admin-verified attribute policy checking
    ├── activity.py                  # Reads on-chain event logs for activity feeds
    ├── admin.py                      # Django admin panel configuration
    ├── templates/                     # All HTML pages
    └── static/mp/                      # CSS and JS
```

---

## 12. Troubleshooting

| Problem | Likely cause / fix |
|---|---|
| `Failed to connect to Ethereum network!` on startup | Your `INFURA_SEPOLIA_URL` in `.env` is missing or wrong — double check it against your Infura dashboard. |
| Registration fails with a blockchain error | Make sure your wallet has Sepolia test ETH (Step 5.4) — registering costs a small gas fee. |
| Google OAuth browser tab doesn't appear, or upload/download hangs | Confirm `credentials.json` is in the project root and matches the exact filename in `.env`'s `GOOGLE_CREDS_FILE`. Delete `token.json` if present and try again. |
| `Transaction reverted on-chain` | Check the transaction hash shown in the error on [Sepolia Etherscan](https://sepolia.etherscan.io) for the exact revert reason — commonly a duplicate username or an already-processed request. |
| Old files won't download after an update to this code | Any file that was granted access under a much older version of this code may need one fresh grant/revoke cycle to republish its access data in the current format. |

---

## 13. Security Notes & Limitations

This is an educational / demonstration project, not a production-hardened system. A few honest caveats:

- Your MetaMask **private key is entered directly into the app** at registration and stored (encrypted-at-rest is *not* currently implemented) in the local database — fine for a personal demo on your own machine, not something to expose on the public internet as-is.
- The Google Drive integration uses your **own personal Google account** — files are stored there, not on some shared third-party server.
- This project currently assumes **one owner's private key per file** for cipher-key derivation; a file jointly owned by multiple users is a known, untested edge case.
- No automated test suite exists yet — everything has been manually verified end-to-end.

---

## 14. Credits

- Access-polynomial key-distribution concept adapted from: Almasian, M. & Shafieinejad, A., *"Secure cloud file sharing scheme using blockchain and attribute-based encryption."*
- Built with Django, web3.py, PyCryptodome, and the Google Drive API.
