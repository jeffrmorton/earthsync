"""Tests for AES-256-GCM encryption utilities."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag
from earthsync_server.services.websocket import (
    decrypt_message,
    encrypt_message,
    generate_encryption_key,
)


class TestGenerateEncryptionKey:
    """Tests for key generation."""

    def test_key_is_32_bytes(self):
        key = generate_encryption_key()
        assert len(key) == 32

    def test_key_is_bytes(self):
        key = generate_encryption_key()
        assert isinstance(key, bytes)

    def test_keys_are_unique(self):
        k1 = generate_encryption_key()
        k2 = generate_encryption_key()
        assert k1 != k2


class TestEncryptDecryptRoundtrip:
    """Tests for encrypt/decrypt symmetry."""

    def test_roundtrip_simple(self):
        key = generate_encryption_key()
        message = {"hello": "world"}
        encrypted = encrypt_message(message, key)
        decrypted = decrypt_message(encrypted, key)
        assert decrypted == message

    def test_roundtrip_complex_payload(self):
        key = generate_encryption_key()
        message = {
            "station_id": "sierra-01",
            "spectrogram": [1.0, 2.0, 3.0],
            "nested": {"a": 1, "b": [True, False, None]},
        }
        encrypted = encrypt_message(message, key)
        decrypted = decrypt_message(encrypted, key)
        assert decrypted == message

    def test_roundtrip_empty_dict(self):
        key = generate_encryption_key()
        message = {}
        encrypted = encrypt_message(message, key)
        decrypted = decrypt_message(encrypted, key)
        assert decrypted == message

    def test_roundtrip_numeric_values(self):
        key = generate_encryption_key()
        message = {"int_val": 42, "float_val": 3.14, "neg": -1}
        encrypted = encrypt_message(message, key)
        decrypted = decrypt_message(encrypted, key)
        assert decrypted == message


class TestEncryptDifferentNonces:
    """Tests for nonce uniqueness."""

    def test_same_message_different_ciphertext(self):
        key = generate_encryption_key()
        message = {"test": "data"}
        ct1 = encrypt_message(message, key)
        ct2 = encrypt_message(message, key)
        assert ct1 != ct2

    def test_encrypted_format_has_colon_separator(self):
        key = generate_encryption_key()
        encrypted = encrypt_message({"a": 1}, key)
        assert ":" in encrypted
        parts = encrypted.split(":")
        assert len(parts) == 2


class TestDecryptWrongKey:
    """Tests for decryption failure with wrong key."""

    def test_wrong_key_raises(self):
        key1 = generate_encryption_key()
        key2 = generate_encryption_key()
        encrypted = encrypt_message({"secret": "data"}, key1)
        with pytest.raises(InvalidTag):
            decrypt_message(encrypted, key2)
