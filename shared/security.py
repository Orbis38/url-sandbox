"""Persistent session configuration, bounded input and login throttling."""
from datetime import datetime
from hashlib import sha256
from os import environ
from pathlib import Path
from time import time
from pymongo import ReturnDocument


def load_session_secret():
    secret = environ.get('URL_SANDBOX_SESSION_SECRET')
    if not secret:
        filename = environ.get('URL_SANDBOX_SESSION_SECRET_FILE', '/run/secrets/flask_session_key')
        try:
            secret = Path(filename).read_text().strip()
        except OSError:
            raise RuntimeError('A persistent Flask session secret must be configured') from None
    if len(secret) < 48:
        raise RuntimeError('The Flask session secret must contain at least 48 characters')
    return secret


def bounded_timeout(value, name, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f'{name} must be an integer between 1 and {maximum}')
    try:
        number = int(value)
    except ValueError:
        raise ValueError(f'{name} must be an integer between 1 and {maximum}') from None
    if not 1 <= number <= maximum:
        raise ValueError(f'{name} must be between 1 and {maximum} seconds')
    return number


def validate_timeouts(data):
    return {name: bounded_timeout(data.get(name, default), name, maximum) for name, default, maximum in
            [('url_timeout', 10, 60), ('analyzer_timeout', 60, 120), ('interactive_timeout', 300, 900)]}


def login_attempt(collection, login, address, now=None):
    now = time() if now is None else now
    window = int(now // 900)
    expires = datetime.utcfromtimestamp((window + 1) * 900)
    allowed = True
    account_id = None
    for scope, value, limit in [('account', login, 10), ('address', address, 30)]:
        bucket = f'{scope}:{window}:{sha256(str(value).encode()).hexdigest()}'
        if scope == 'account':
            account_id = bucket
        result = collection.find_one_and_update({'_id': bucket},
            {'$inc': {'count': 1}, '$setOnInsert': {'expires_at': expires}},
            upsert=True, return_document=ReturnDocument.AFTER)
        allowed = allowed and result is not None and result['count'] <= limit
    return allowed, max(1, int((window + 1) * 900 - now)), account_id
