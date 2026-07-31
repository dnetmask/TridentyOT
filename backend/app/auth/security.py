"""Password hashing and session token helpers.

Uses only the standard library (hashlib's PBKDF2-HMAC-SHA256, ~OWASP 2023
guidance on iteration count) rather than pulling in bcrypt/passlib, so the
app has no extra native/compiled dependency to install -- relevant since it
targets air-gapped OT deployments and Docker builds without guaranteed
internet access.
"""

import hashlib
import hmac
import os
import secrets

_PBKDF2_ITERATIONS = 260_000
_SALT_BYTES = 16
_TOKEN_BYTES = 32


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Returns (salt_hex, hash_hex)."""
    salt = salt if salt is not None else os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    _, computed_hash_hex = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(computed_hash_hex, expected_hash_hex)


def generate_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    # Tokens are bearer credentials -- store only their hash, so a database
    # leak alone doesn't hand out valid sessions (the raw token is only ever
    # seen once, at login, by the client).
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
