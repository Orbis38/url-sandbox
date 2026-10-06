"""Per-user API credentials. Plaintext tokens are returned only at creation."""

from datetime import datetime
from hashlib import sha256
from secrets import token_urlsafe


def token_digest(token):
    return sha256(token.encode('utf-8')).hexdigest()


def create_api_key(collection, owner_id, label):
    label = label.strip()
    if not label or len(label) > 80:
        raise ValueError('Choose a name between 1 and 80 characters.')
    collection.create_index('digest', unique=True)
    collection.create_index('owner_id')
    token = 'usp_' + token_urlsafe(32)
    collection.insert_one({
        'owner_id': owner_id, 'label': label, 'digest': token_digest(token),
        'prefix': token[:12], 'created_at': datetime.utcnow(),
        'last_used_at': None, 'revoked_at': None,
    })
    return token


def authenticate_api_key(collection, token):
    if not isinstance(token, str) or not token.startswith('usp_') or len(token) > 128:
        return None
    key = collection.find_one_and_update(
        {'digest': token_digest(token), 'revoked_at': None},
        {'$set': {'last_used_at': datetime.utcnow()}})
    if not key:
        return None
    return key['owner_id']


def revoke_api_key(collection, owner_id, key_id):
    return collection.update_one(
        {'_id': key_id, 'owner_id': owner_id, 'revoked_at': None},
        {'$set': {'revoked_at': datetime.utcnow()}}).modified_count == 1
