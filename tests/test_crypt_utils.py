"""Tests for crypt_utils.CryptoUtils."""

import nacl.exceptions
import nacl.pwhash
import nacl.secret
import pytest

from crypt_utils import CryptoUtils


def test_generate_salt_has_correct_length():
    salt = CryptoUtils.generate_salt()
    assert len(salt) == nacl.pwhash.argon2i.SALTBYTES


def test_generate_salt_is_random():
    assert CryptoUtils.generate_salt() != CryptoUtils.generate_salt()


def test_derive_key_has_correct_length():
    salt = CryptoUtils.generate_salt()
    key = CryptoUtils.derive_key("password", salt)
    assert len(key) == nacl.secret.SecretBox.KEY_SIZE


def test_derive_key_is_deterministic():
    salt = CryptoUtils.generate_salt()
    key1 = CryptoUtils.derive_key("password", salt)
    key2 = CryptoUtils.derive_key("password", salt)
    assert key1 == key2


def test_derive_key_differs_for_different_passwords():
    salt = CryptoUtils.generate_salt()
    key1 = CryptoUtils.derive_key("password1", salt)
    key2 = CryptoUtils.derive_key("password2", salt)
    assert key1 != key2


def test_derive_key_differs_for_different_salts():
    key1 = CryptoUtils.derive_key("password", CryptoUtils.generate_salt())
    key2 = CryptoUtils.derive_key("password", CryptoUtils.generate_salt())
    assert key1 != key2


def test_derive_key_rejects_empty_password():
    with pytest.raises(ValueError):
        CryptoUtils.derive_key("", CryptoUtils.generate_salt())


def test_derive_key_rejects_wrong_salt_size():
    with pytest.raises(ValueError):
        CryptoUtils.derive_key("password", b"too_short")


def test_encrypt_decrypt_roundtrip():
    key = CryptoUtils.derive_key("password", CryptoUtils.generate_salt())
    plaintext = b"Secret message for encryption test"

    encrypted = CryptoUtils.encrypt(plaintext, key)
    decrypted = CryptoUtils.decrypt(encrypted, key)

    assert decrypted == plaintext
    assert encrypted != plaintext


def test_decrypt_with_wrong_key_raises():
    salt = CryptoUtils.generate_salt()
    key = CryptoUtils.derive_key("password", salt)
    wrong_key = CryptoUtils.derive_key("wrong_password", salt)

    encrypted = CryptoUtils.encrypt(b"secret data", key)

    with pytest.raises(nacl.exceptions.CryptoError):
        CryptoUtils.decrypt(encrypted, wrong_key)


def test_decrypt_tampered_data_raises():
    key = CryptoUtils.derive_key("password", CryptoUtils.generate_salt())
    encrypted = bytearray(CryptoUtils.encrypt(b"secret data", key))
    encrypted[-1] ^= 0xFF  # flip a bit in the ciphertext/MAC

    with pytest.raises(nacl.exceptions.CryptoError):
        CryptoUtils.decrypt(bytes(encrypted), key)


def test_encrypt_rejects_wrong_key_size():
    with pytest.raises(ValueError):
        CryptoUtils.encrypt(b"data", b"too_short")


def test_decrypt_rejects_wrong_key_size():
    with pytest.raises(ValueError):
        CryptoUtils.decrypt(b"data", b"too_short")


def test_base64_roundtrip():
    data = b"\x00\x01\xff binary data \xfe"
    encoded = CryptoUtils.encode_base64(data)
    assert isinstance(encoded, str)
    assert CryptoUtils.decode_base64(encoded) == data


def test_encode_base64_rejects_non_bytes():
    with pytest.raises(TypeError):
        CryptoUtils.encode_base64("not bytes")


def test_decode_base64_rejects_invalid_string():
    with pytest.raises(ValueError):
        CryptoUtils.decode_base64("not valid base64!!!")
