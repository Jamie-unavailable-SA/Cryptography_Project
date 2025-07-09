"""
Multiple-mode encryption/decryption utilities

Supported modes:
    - CBC
    - CTR
    - CFB
    - OFB
    - GCM

All binary artifacts(key, iv/nonce, tag, ciphertext) are Base64-encoded in order to be able to travel safely through comm mediums(email e.t.c)
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, asdict
from typing import Final, Tuple, Optional, Dict, Any
from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore

AES_KEY_BYTES: Final[int] = 32
AES_BLOCK_BYTES: Final[int] = 16

SUPPORTED_MODES: Final[set[str]] = {"CBC", "CTR", "CFB", "OFB", "GCM"}

NONCE_SIZES: Final[dict[str, int]] = {
    "CBC": 16,
    "CFB": 16,
    "OFB": 16,
    "CTR": 8,
    "GCM": 12,
}

def _random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

@dataclass (frozen=True)
class EncryptedPacket:
    """Serializable container for encrypted data and related parameters."""

    mode: str
    ciphertext_b64: str
    key_b64: str
    iv_or_nonce_b64: str
    tag_b64: Optional[str] = None

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(asdict(self), indent=indent)
    
    @classmethod
    def from_json(cls, data: str | bytes | Dict[str, Any]) -> "EncryptedPacket":
        if isinstance(data, (str, bytes)):
            payload = json.loads(data)
        else:
            payload = data
        return cls(**payload)
    
    def to_tuple(self) -> Tuple[str, str, str, Optional[str]]:
        return(
            self.mode,
            self.ciphertext_b64,
            self.key_b64,
            self.iv_or_nonce_b64,
            self.tag_b64,
        )

def generate_key() -> bytes:
    """Returns a fresh 256-bit key"""
    return _random_bytes(AES_KEY_BYTES)

def encrypt_message(
    plaintext: str,
    *,
    key: Optional[bytes] = None,
    mode: str = "CBC",
    associated_data: bytes | None = None,
) -> EncryptedPacket:
    """
    Encrypts a plaintext string using AES and returns an EncryptedPacket.
    """
    mode = mode.upper()
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode: '{mode}'")

    if key is None:
        key = generate_key()

    if len(key) != AES_KEY_BYTES:
        raise ValueError("Key must be 32 bytes (256 bits).")

    nonce = _random_bytes(NONCE_SIZES[mode])

    if mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=nonce)
        padded = pad(plaintext.encode(), AES_BLOCK_BYTES)
        ciphertext = cipher.encrypt(padded)
        tag = None
    elif mode == "GCM":
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            cipher.update(associated_data)
        ciphertext, tag_bytes = cipher.encrypt_and_digest(plaintext.encode())
        tag = base64.b64encode(tag_bytes).decode()
    elif mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext.encode())
        tag = None
    elif mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv=nonce, segment_size=128)
        ciphertext = cipher.encrypt(plaintext.encode())
        tag = None
    elif mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB, iv=nonce)
        ciphertext = cipher.encrypt(plaintext.encode())
        tag = None
    else:
        raise AssertionError("Unreachable")

    return EncryptedPacket(
        mode=mode,
        ciphertext_b64=base64.b64encode(ciphertext).decode(),
        key_b64=base64.b64encode(key).decode(),
        iv_or_nonce_b64=base64.b64encode(nonce).decode(),
        tag_b64=tag,
    )


def decrypt_message(
        packet: EncryptedPacket | str | bytes | Dict[str, Any],
        *,
        associated_data: bytes | None = None,
) -> str:
    """
    Decrypts the EncryptedPacket to return the plaintext
    """

    if not isinstance(packet, EncryptedPacket):
        packet = EncryptedPacket.from_json(packet)

    mode = packet.mode.upper()
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode: '{mode}'")
    
    ciphertext = base64.b64decode(packet.ciphertext_b64)
    key = base64.b64decode(packet.key_b64)
    nonce = base64.b64decode(packet.iv_or_nonce_b64)

    if len(key) != AES_KEY_BYTES:
        raise ValueError("Invalid key length in packet.")
    
    if mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv = nonce)
        padded = cipher.decrypt(ciphertext)
        plaintext_bytes = unpad(padded, AES_BLOCK_BYTES)

    elif mode == "GCM":

        if packet.tag_b64 is None:
            raise ValueError("Missing authentication tag for GCM mode.")
        
        tag = base64.b64decode(packet.tag_b64)
        cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)

        if associated_data:
            cipher.update(associated_data)
        
        plaintext_bytes = cipher.decrypt_and_verify (ciphertext, tag)

    elif mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)
        plaintext_bytes = cipher.decrypt(ciphertext)

    elif mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv = nonce, segment_size = 128)
        plaintext_bytes = cipher.decrypt(ciphertext)

    elif mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB, iv = nonce)
        plaintext_bytes = cipher.decrypt(ciphertext)

    else:
        raise AssertionError("unreachable")
    
    return plaintext_bytes.decode()

#Testing

if __name__ == "__namin__":
    import argparse, sys, textwrap

    parser = argparse.ArgumentParser(
        description = "Encrypt/Decrypt test for the AES modes",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent(
            """
            Examples:
                python aes_cipher.py -m GCM "Secret"
                python aes_cipher.py --mode CTR "Hello world" | jq
            """
        ),
    )
    parser.add_argument("message", help = "Message to emcrypt/decrypt")
    parser.add_argument("-m", "--mode", default = "CBC", help = "AES mode to use")
    args = parser.parse_args()
    print("[+] Encrypting...")
    pkt = encrypt_message(args.message, mode=args.mode)
    json_blob = pkt.to_json(indent = 2)
    print(json_blob)
    print("\n[+] Decrypting...")
    result = decrypt_message(json_blob)
    print("plaintext: ", result)

    if result != args.message:
        print("[ERROR] Mismatch!", file = sys.stderr)
        sys.exit(1)
    
    print("[OK] Round trip successful")