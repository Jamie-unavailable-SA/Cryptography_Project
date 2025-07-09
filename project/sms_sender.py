"""
Core cryptographic and SMS functionality for secure messaging
Combines AES encryption with OTP generation and SMS sending
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Tuple, Final, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import http.client

# Constants
DEFAULT_OTP_LENGTH: Final[int] = 6
DEFAULT_TTL_SECONDS: Final[int] = 300
AES_KEY_BYTES: Final[int] = 32
AES_BLOCK_BYTES: Final[int] = 16
PBKDF2_ITERATIONS: Final[int] = 100_000
PBKDF2_SALT_BYTES: Final[int] = 16

# Configuration (replace with your actual values)
INFOBIP_BASE_URL = "e5446r.api.infobip.com"  # Updated to correct domain
INFOBIP_API_KEY = "52aad71abd16f68f4513efd1e34de6a5-ec03096b-3ffc-4971-8ea6-42e0d94d6cb7"
SMS_SENDER = "SecureMsg"  # Your approved sender name/number


@dataclass
class OTPRecord:
    """Container for OTP data including code, salt, and expiration"""
    code: str
    salt: bytes
    expires_at: float

    def salt_b64(self) -> str:
        return base64.b64encode(self.salt).decode()

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass(frozen=True)
class EncryptedPacket:
    """Container for encrypted data and related parameters"""
    ciphertext_b64: str
    key_b64: str
    iv_b64: str

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> "EncryptedPacket":
        return cls(**json.loads(data))


def generate_otp(length: int = DEFAULT_OTP_LENGTH,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS) -> OTPRecord:
    """Generate a random OTP with salt and expiration"""
    if not (4 <= length <= 10):
        raise ValueError("OTP length must be between 4 and 10 digits")

    code = ''.join(secrets.choice('0123456789') for _ in range(length))
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    expires_at = time.time() + ttl_seconds
    return OTPRecord(code, salt, expires_at)


def derive_key_from_otp(otp_record: OTPRecord) -> bytes:
    """Derive a cryptographic key from OTP using PBKDF2"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        otp_record.code.encode(),
        otp_record.salt,
        PBKDF2_ITERATIONS,
        dklen=AES_KEY_BYTES
    )


def verify_otp(provided_code: str, otp_record: OTPRecord) -> bool:
    """Verify OTP with constant-time comparison and check expiration"""
    if otp_record.is_expired():
        return False
    return hmac.compare_digest(provided_code, otp_record.code)


def encrypt_message(plaintext: str) -> Tuple[EncryptedPacket, bytes]:
    """Encrypt message using AES-256-CBC with generated key"""
    key = secrets.token_bytes(AES_KEY_BYTES)
    iv = secrets.token_bytes(AES_BLOCK_BYTES)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pad(plaintext.encode(), AES_BLOCK_BYTES)
    ciphertext = cipher.encrypt(padded)

    packet = EncryptedPacket(
        ciphertext_b64=base64.b64encode(ciphertext).decode(),
        key_b64=base64.b64encode(key).decode(),
        iv_b64=base64.b64encode(iv).decode()
    )

    return packet, key


def decrypt_message(packet: EncryptedPacket, key: bytes) -> str:
    """Decrypt message using provided key"""
    ciphertext = base64.b64decode(packet.ciphertext_b64)
    iv = base64.b64decode(packet.iv_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)
    plaintext_bytes = unpad(padded, AES_BLOCK_BYTES)

    return plaintext_bytes.decode()


def send_sms(phone_number: str, message: str) -> bool:
    """Send SMS using Infobip API with proper error handling"""
    if not phone_number.startswith('+'):
        phone_number = f"+{phone_number}"

    payload = json.dumps({
        "messages": [
            {
                "destinations": [{"to": phone_number}],
                "from": SMS_SENDER,
                "text": message
            }
        ]
    })

    headers = {
        'Authorization': f'App {INFOBIP_API_KEY}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    try:
        conn = http.client.HTTPSConnection(INFOBIP_BASE_URL)
        conn.request("POST", "/sms/2/text/advanced", payload, headers)
        res = conn.getresponse()

        if res.status in (200, 201):
            return True
        else:
            print(f"SMS sending failed. Status: {res.status}, Response: {res.read().decode()}")
            return False
    except Exception as e:
        print(f"Error sending SMS: {str(e)}")
        return False