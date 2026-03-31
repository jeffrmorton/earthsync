"""WebSocket broadcast manager with AES-256-GCM encryption."""

from __future__ import annotations

import base64
import json
import os

import structlog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = structlog.get_logger()


def generate_encryption_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(message: dict, key: bytes) -> str:
    """Encrypt a message dict using AES-256-GCM. Returns base64 encoded 'nonce:ciphertext'."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    plaintext = json.dumps(message).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce).decode() + ":" + base64.b64encode(ciphertext).decode()


def decrypt_message(encrypted: str, key: bytes) -> dict:
    """Decrypt an AES-256-GCM encrypted message. Returns the original dict."""
    nonce_b64, ct_b64 = encrypted.split(":", 1)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ct_b64)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))
