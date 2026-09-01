"""
activity.py — Blockchain activity feed helpers.

Provides personal activity feeds for users and owners by reading events
from the SecureShare smart contract. ActivityLog entries are stored locally
in Django for application-level activity tracking.
"""

from decouple import config
from .chain_client import w3, CONTRACT_ABI, CONTRACT_ADDRESS


# ---- LOCAL ACTIVITY LOGGING ----
# Stores an application action in Django's ActivityLog table.
def log_activity(user, action, detail, tx_hash=''):
    """
    Record an activity at the moment the corresponding action occurs.
    """
    from .models import ActivityLog
    ActivityLog.objects.create(user=user, action=action, detail=detail, tx_hash=tx_hash)


# -------------------- BLOCKCHAIN CONTRACT CONFIGURATION ------------------------
# Connect to the deployed SecureShare smart contract using the configured
# contract address and ABI.
CONTRACT = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
# Starting block for event searches. Set CONTRACT_DEPLOY_BLOCK in .env
# to avoid scanning the blockchain from block 0.
DEPLOY_BLOCK = config('CONTRACT_DEPLOY_BLOCK', default=0, cast=int)
# Maximum block range used for a single event query.
LOG_CHUNK = 5000


# ----------------------------------------------------------------------------
# BLOCKCHAIN EVENT HELPERS 
# ----------------------------------------------------------------------------

# Fetches contract events in smaller block ranges to avoid RPC provider limits.
def _get_logs_chunked(event, from_block, to_block, argument_filters=None):
    logs = []
    start = from_block
    while start <= to_block:
        end = min(start + LOG_CHUNK - 1, to_block)
        logs.extend(event.get_logs(
            fromBlock=start, toBlock=end,
            argument_filters=argument_filters or {}
        ))
        start = end + 1
    return logs


# Decodes the request data stored by the smart contract.
def _decode_request(request_id):
    """Return the requested filename and username from an on-chain request."""
    try:
        req_bytes = CONTRACT.functions.getRequest(request_id).call()
        parts = req_bytes.decode().split('\\')
        return parts[0], parts[1]
    except Exception:
        return '(unknown file)', '(unknown user)'


# ---- OWNER ACTIVITY ----
# Returns blockchain events associated with actions performed by a file owner.
def get_owner_activity(address, limit=25):
    """
    Activity feed for a Data Owner: registrations, and every grant/reject decision.
    """
    latest = w3.eth.block_number
    events = []

    for log in _get_logs_chunked(CONTRACT.events.AccessGranted, DEPLOY_BLOCK, latest, {'user': address}):
        filename, requester = _decode_request(log['args']['requestId'])
        events.append({
            'type': 'Access Granted',
            'detail': f'You granted "{requester}" access to "{filename}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    for log in _get_logs_chunked(CONTRACT.events.AccessRejected, DEPLOY_BLOCK, latest, {'user': address}):
        filename, requester = _decode_request(log['args']['requestId'])
        events.append({
            'type': 'Access Rejected',
            'detail': f'You rejected "{requester}"\'s request for "{filename}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    for log in _get_logs_chunked(CONTRACT.events.UserRegistered, DEPLOY_BLOCK, latest, {'userAddress': address}):
        events.append({
            'type': 'Registered',
            'detail': f'You registered as "{log["args"]["username"]}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    events.sort(key=lambda e: e['block'], reverse=True)
    return events[:limit]


# ---- USER ACTIVITY ----
# Returns blockchain events associated with access requests made by a user.
def get_user_activity(address, limit=25):
    """
    Activity feed for a Data User, including registrations and access
    requests made by this wallet address.
    """
    latest = w3.eth.block_number
    events = []

    for log in _get_logs_chunked(CONTRACT.events.AccessRequested, DEPLOY_BLOCK, latest, {'user': address}):
        filename, _ = _decode_request(log['args']['requestId'])
        events.append({
            'type': 'Access Requested',
            'detail': f'You requested access to "{filename}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    for log in _get_logs_chunked(CONTRACT.events.UserRegistered, DEPLOY_BLOCK, latest, {'userAddress': address}):
        events.append({
            'type': 'Registered',
            'detail': f'You registered as "{log["args"]["username"]}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    events.sort(key=lambda e: e['block'], reverse=True)
    return events[:limit]


# ---- ADMIN ACTIVITY ----
# Returns events from all wallets. Use only for admin/staff views.
def get_all_activity(limit=50):
    """
    Site-wide blockchain activity feed for trusted administrative views.
    """
    latest = w3.eth.block_number
    events = []

    for log in _get_logs_chunked(CONTRACT.events.AccessGranted, DEPLOY_BLOCK, latest, {}):
        filename, requester = _decode_request(log['args']['requestId'])
        events.append({
            'type': 'Access Granted',
            'detail': f'{log["args"]["user"]} granted "{requester}" access to "{filename}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    for log in _get_logs_chunked(CONTRACT.events.AccessRejected, DEPLOY_BLOCK, latest, {}):
        filename, requester = _decode_request(log['args']['requestId'])
        events.append({
            'type': 'Access Rejected',
            'detail': f'{log["args"]["user"]} rejected "{requester}"\'s request for "{filename}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    for log in _get_logs_chunked(CONTRACT.events.AccessRequested, DEPLOY_BLOCK, latest, {}):
        filename, _ = _decode_request(log['args']['requestId'])
        events.append({
            'type': 'Access Requested',
            'detail': f'{log["args"]["user"]} requested access to "{filename}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    for log in _get_logs_chunked(CONTRACT.events.UserRegistered, DEPLOY_BLOCK, latest, {}):
        events.append({
            'type': 'Registered',
            'detail': f'{log["args"]["userAddress"]} registered as "{log["args"]["username"]}"',
            'block': log['blockNumber'],
            'tx_hash': log['transactionHash'].hex(),
        })

    events.sort(key=lambda e: e['block'], reverse=True)
    return events[:limit]


# ---- COMBINED PERSONAL ACTIVITY ----
# Merges owner and user events for the Activities page.
def get_full_activity(address, limit=200):
    """
    Combines owner and user activity for a wallet and removes duplicate
    events before returning the newest entries.
    """
    owner_events = get_owner_activity(address, limit=limit)
    user_events = get_user_activity(address, limit=limit)

    seen = set()
    merged = []
    for e in owner_events + user_events:
        key = (e['type'], e['tx_hash'])
        if key in seen:
            continue
        seen.add(key)
        merged.append(e)

    merged.sort(key=lambda e: e['block'], reverse=True)
    return merged[:limit]
