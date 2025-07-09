# otp_utils_py27.py
"""
One-time passcode utilities for Python 2.7

- Creates a 6-digit code
- Supports cryptographic key derivation (PBKDF2-HMAC-SHA256)
- Provides an in-memory OTPStore for testing/demo
"""

import base64
import hashlib
import hmac
import secrets
import time

try:
    import secrets
except ImportError:
    import os
    import random
    class secrets:
        @staticmethod
        def randbelow(n):
            return int(random.random() * n)

        @staticmethod
        def token_bytes(n):
            return os.urandom(n)

# Constants
DEFAULT_OTP_LENGTH = 6
DEFAULT_TTL_SECONDS = 300
PBKDF2_ITERATIONS = 100000
PBKDF2_SALT_BYTES = 16
AES_KEY_BYTES = 32


def _random_digits(n):
    """
    Return n random decimal digits as a string with no leading zeros
    """
    rng_range = 10 ** n
    number = secrets.randbelow(rng_range - 10 ** (n - 1)) + 10 ** (n - 1)
    return str(number)


def _pbkdf2_key(otp, salt, length=AES_KEY_BYTES):
    """
    Derive a cryptographic key from a short OTP using PBKDF2_HMAC_SHA256
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        otp.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=length
    )


class OTPRecord(object):
    def __init__(self, code, salt, expires_at):
        self.code = code
        self.salt = salt
        self.expires_at = expires_at

    def salt_b64(self):
        return base64.b64encode(self.salt)

    def to_tuple(self):
        return (self.code, self.salt_b64(), self.expires_at)

    @classmethod
    def from_tuple(cls, data):
        code, salt_b64, exp = data
        return cls(code, base64.b64decode(salt_b64), exp)


def generate_otp(length=DEFAULT_OTP_LENGTH, ttl_seconds=DEFAULT_TTL_SECONDS):
    """
    Generate a numeric OTP, random salt, and expiry timestamp.
    """
    if length < 4 or length > 10:
        raise ValueError("OTP length must be between 4 and 10 digits")

    code = _random_digits(length)
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    expires_at = time.time() + ttl_seconds
    return OTPRecord(code, salt, expires_at)


def derive_key_from_otp(otp_record):
    """
    Stretch otp_record.code into a 256-bit AES key using its salt
    """
    return _pbkdf2_key(otp_record.code, otp_record.salt)


def verify_otp(provided_code, otp_record):
    """
    Constant-time comparison of provided_code with stored record and expiry check.
    """
    current = time.time()

    if current > otp_record.expires_at:
        return False

    return hmac.compare_digest(provided_code.encode('utf-8'), otp_record.code.encode('utf-8'))


class OTPStore(object):
    def __init__(self):
        self._store = {}

    def save(self, identifier, otp_record):
        self._store[identifier] = otp_record

    def validate(self, identifier, provided_code):
        rec = self._store.get(identifier)
        if rec is None:
            return False

        valid = verify_otp(provided_code, rec)

        if valid:
            # One-time use: remove from store
            self._store.pop(identifier, None)

        return valid

    def get_key(self, identifier):
        rec = self._store.get(identifier)
        if rec is None:
            return None

        return derive_key_from_otp(rec)


# CLI test
if __name__ == "__main__":
    print("[+] Generating OTP...")
    store = OTPStore()
    record = generate_otp(length=6)
    store.save("john@example.com", record)

    print("OTP:", record.code)
    print("Expires at:", time.ctime(record.expires_at))
    print("Derived key (Base64):", base64.b64encode(derive_key_from_otp(record)))

    try:
        user_input = raw_input("Enter OTP to verify: ")  # For Python 2.7
    except NameError:
        user_input = input("Enter OTP to verify: ")  # For Python 3.x

    if store.validate("john@example.com", user_input):
        print("[✓] OTP valid")
    else:
        print("[X] OTP invalid or expired")
