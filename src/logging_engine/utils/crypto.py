"""
logging_engine/utils/crypto.py — cryptographic helpers

What it will do
Hashing and optional signature helpers for log integrity (sha256/sha1, HMAC wrappers).

How it will work
Exposes functions like sha256_hex(data), hmac_sign(data, key). Called by writers if signature required.

Concurrency & resources
Stateless; low CPU (hashing). Thread-safe.

Files read/written / artifacts
No files by itself; writers may store hashes in metadata files.

This module can be run standalone to perform self-tests.
"""

import hashlib
import hmac
import base64
import secrets
import argparse
from typing import Union

BytesLike = Union[bytes, bytearray]


def _to_bytes(data: Union[str, BytesLike]) -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return str(data).encode('utf-8')


def sha256_hex(data: Union[str, BytesLike]) -> str:
    """Return SHA-256 hex digest of data."""
    b = _to_bytes(data)
    return hashlib.sha256(b).hexdigest()


def sha1_hex(data: Union[str, BytesLike]) -> str:
    """Return SHA-1 hex digest of data."""
    b = _to_bytes(data)
    return hashlib.sha1(b).hexdigest()


def hmac_sha256_hex(data: Union[str, BytesLike], key: Union[str, BytesLike]) -> str:
    """Return HMAC-SHA256 hex digest for data using key."""
    b = _to_bytes(data)
    k = _to_bytes(key)
    return hmac.new(k, b, hashlib.sha256).hexdigest()


def hmac_sha1_hex(data: Union[str, BytesLike], key: Union[str, BytesLike]) -> str:
    """Return HMAC-SHA1 hex digest for data using key."""
    b = _to_bytes(data)
    k = _to_bytes(key)
    return hmac.new(k, b, hashlib.sha1).hexdigest()


def generate_hmac_key(length: int = 32) -> str:
    """Generate a random key suitable for HMAC. Returns base64 encoded string."""
    raw = secrets.token_bytes(length)
    return base64.b64encode(raw).decode('ascii')


def verify_hmac_hex(expected_hex: str, data: Union[str, BytesLike], key: Union[str, BytesLike], algo: str = 'sha256') -> bool:
    """Constant-time verify HMAC hex digest. `algo` can be 'sha256' or 'sha1'."""
    if algo == 'sha256':
        computed = hmac_sha256_hex(data, key)
    elif algo == 'sha1':
        computed = hmac_sha1_hex(data, key)
    else:
        raise ValueError('Unsupported algorithm: ' + str(algo))
    return hmac.compare_digest(computed, expected_hex)


# Small CLI for self-tests
def _parse_args():
    p = argparse.ArgumentParser(description='crypto.py self-test runner')
    p.add_argument('--test', action='store_true', help='Run a small hashing/HMAC self-test')
    p.add_argument('--key-length', type=int, default=32, help='HMAC key length in bytes for generation test')
    return p.parse_args()


def _run_tests(key_length: int = 32):
    print('Running crypto helper tests...')
    sample = 'The quick brown fox jumps over the lazy dog'
    print('Sample:', sample)
    print('SHA256:', sha256_hex(sample))
    print('SHA1  :', sha1_hex(sample))
    key = generate_hmac_key(key_length)
    print('Generated HMAC key (base64):', key)
    sig = hmac_sha256_hex(sample, base64.b64decode(key))
    print('HMAC-SHA256:', sig)
    ok = verify_hmac_hex(sig, sample, base64.b64decode(key), algo='sha256')
    print('Verify HMAC-SHA256:', ok)
    tampered = 'The quick brown fox'
    print('Verify with tampered data (should be False):', verify_hmac_hex(sig, tampered, base64.b64decode(key), algo='sha256'))
    print('All crypto helpers OK')


if __name__ == '__main__':
    args = _parse_args()
    if args.test:
        _run_tests(args.key_length)
    else:
        print('crypto helpers in good condition')
