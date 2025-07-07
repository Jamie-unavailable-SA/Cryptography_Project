"""
One-time passcode utilities

-creates a 6 digit code
-Supports optional cryptographic key derivation (PBKDF2‑HMAC‑SHA256) so the
  same short OTP can be stretched into a 256‑bit AES key.
-Provides an in‑memory *OTPStore* for quick demos / CLI tests.
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

DEFAULT_OTP_LENGTH: int = 6
DEFAULT_TTL_SECONDS: int = 300
PBKDF2_ITERATIONS: int = 100_000
PBKDF2_SALT_BYTES: int = 16
AES_KEY_BYTES: int = 32

def _random_digits(n: int) -> str:
    """
    returning n random decimal digits as a string with no leading zeros
    """
    rng_range = 10 ** 1
    number = 10 ** nnumber = secrets.randbelow(rng_range - 10 ** (n - 1)) + 10 ** (n - 1)
    return str(number)

def _pbkdf2_key(otp: str, salt: bytes, *, length: int = AES_KEY_BYTES) -> bytes:
    """
    Deriving a cryptographic key from a short OTP using PBKDF2_HMAC_SHA256
    """
    return hashlib.pbkdf2_hmac(
        otp.encode(),
        salt,
        PBKDF2_ITERATIONS,
        dklen = length,
    )

@dataclass
class OTPRecord:
    code: str
    salt: bytes
    expires_at: float

    def salt_b64(self) -> str:
        return base64.b64encode(self.salt).decode()
    
    def to_tuple(self) -> Tuple[str, str, float]:
        return (self.code, self.salt_b64(), self.expires_at)
    
    @classmethod
    def from_tuple(cls, data: Tuple[str, str, float]) -> "OTPRecord":
        code, salt_b64, exp = data
        return cls(code, base64.b64decode(salt_b64), exp)

def generate_otp(
        *,
        length: int = DEFAULT_OTP_LENGTH,
        ttl_seconds: int = DEFAULT_TTL_SECONDS
) -> OTPRecord:
    # Generating a numeric OTP plus random salt and expiry timestamp.
    if not (4 <= length <= 10):
        raise ValueError("OTP length must be between 4 and 10 digits")
    
    code = _random_digits(length)
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    expires_at = time.time() + ttl_seconds
    return OTPRecord(code, salt, expires_at)

def derive_key_from_otp(otp_record: OTPRecord) -> bytes:
    # Stretching otp_record.code into a 256-bit key using its salt
    return _pbkdf2_key(otp_record.code, otp_record.salt)

def verify_otp(provided_code: str, otp_record: OTPRecord) -> bool:
    # Constant‑time comparison of *provided_code* with record and checks expiry.
    current = time.time()

    if current > otp_record.expires_at:
        return False
    
    return hmac.compare_digest(provided_code, otp_record.code)

class OTPStore:
    # used for testing
    def __init__(self) -> None:
        self._store: Dict[str, OTPRecord] = {}

    def create(self, identifier: str, provided_code: str) -> bool:
        rec = self._store.get(identifier)
        
        if rec is None:
            return False
        
        valid = verify_otp(provided_code, rec)

        if valid:
            # Optional: one‑time use → delete
            self._store.pop(identifier, None)
        
        return valid
    
    def get_key(self, identifier: str) -> Optional[bytes]:
        rec = self._store.get(identifier)

        if rec is None:
            return None
        
        return derive_key_from_otp(rec)
    
if __name__ == "__main__":
    print("[+] Generating OTP...")
    store = OTPStore()
    record = store.create("john@example.com", length = 6)
    print("OTP: ", record.code)
    print("Expires at: ", time.ctime(record.expires_at))
    print("Derived key (Base64): ", base64.b64encode(derive_key_from_otp(record)).decode())

    user_input = input("Enter OTP to verity: ")
    
    if store.validate("john@example.com", user_input):
        print("[✓] OTP valid")

    else:
        print("[X] OTP invalid or expired")