"""
Cryptography Utilities Module - Provides secure encryption operations.

This module wraps PyNaCl cryptographic functions for secure password-based
encryption using Argon2 key derivation and XSalsa20-Poly1305 authenticated encryption.
"""

import base64
import logging
from typing import Union

import nacl.secret
import nacl.utils
import nacl.pwhash
import nacl.exceptions

logger = logging.getLogger(__name__)


class CryptoUtils:
    """
    Cryptographic utility functions for secure data encryption.

    Uses NaCl library for:
    - Argon2i key derivation from passwords
    - XSalsa20-Poly1305 authenticated encryption
    - Secure random salt generation
    """

    @staticmethod
    def generate_salt() -> bytes:
        """
        Generate a cryptographically secure random salt.

        Returns:
            Random salt bytes suitable for Argon2 key derivation

        Note:
            Salt size is determined by nacl.pwhash.argon2i.SALTBYTES (16 bytes)
        """
        logger.debug("Generating new salt")
        salt = nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES)
        logger.debug(f"Generated {len(salt)} byte salt")
        return salt

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Derive a secure encryption key from password and salt using Argon2.

        Args:
            password: User password (will be encoded as UTF-8)
            salt: Salt bytes (must be 16 bytes for Argon2i)

        Returns:
            Derived key bytes suitable for encryption

        Raises:
            ValueError: If password is empty or salt is wrong size

        Note:
            Uses Argon2i algorithm with default parameters for security
        """
        if not password:
            raise ValueError("Passwort darf nicht leer sein")

        if len(salt) != nacl.pwhash.argon2i.SALTBYTES:
            raise ValueError(
                f"Salt muss {nacl.pwhash.argon2i.SALTBYTES} Bytes lang sein"
            )

        logger.debug("Deriving key from password")
        password_bytes = password.encode("utf-8")

        try:
            key = nacl.pwhash.argon2i.kdf(
                nacl.secret.SecretBox.KEY_SIZE,
                password_bytes,
                salt
            )
            logger.debug(f"Derived {len(key)} byte key")
            return key
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using authenticated encryption (XSalsa20-Poly1305).

        Args:
            data: Plain data bytes to encrypt
            key: Encryption key (must be 32 bytes)

        Returns:
            Encrypted data with nonce prepended

        Raises:
            ValueError: If key is wrong size

        Note:
            The nonce is automatically generated and included in output
        """
        if len(key) != nacl.secret.SecretBox.KEY_SIZE:
            raise ValueError(
                f"Schlüssel muss {nacl.secret.SecretBox.KEY_SIZE} Bytes lang sein"
            )

        logger.debug(f"Encrypting {len(data)} bytes")

        try:
            box = nacl.secret.SecretBox(key)
            encrypted = box.encrypt(data)
            logger.debug(f"Encrypted to {len(encrypted)} bytes")
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt data using authenticated encryption (XSalsa20-Poly1305).

        Args:
            encrypted_data: Encrypted data with nonce prepended
            key: Decryption key (must be 32 bytes)

        Returns:
            Decrypted plain data bytes

        Raises:
            ValueError: If key is wrong size
            nacl.exceptions.CryptoError: If authentication fails or key is wrong
        """
        if len(key) != nacl.secret.SecretBox.KEY_SIZE:
            raise ValueError(
                f"Schlüssel muss {nacl.secret.SecretBox.KEY_SIZE} Bytes lang sein"
            )

        logger.debug(f"Decrypting {len(encrypted_data)} bytes")

        try:
            box = nacl.secret.SecretBox(key)
            decrypted = box.decrypt(encrypted_data)
            logger.debug(f"Decrypted to {len(decrypted)} bytes")
            return decrypted
        except nacl.exceptions.CryptoError as e:
            logger.error("Decryption failed - wrong key or corrupted data")
            raise
        except Exception as e:
            logger.error(f"Unexpected decryption error: {e}")
            raise

    @staticmethod
    def encode_base64(data_bytes: bytes) -> str:
        """
        Encode bytes to base64 string (for storage/transmission).

        Args:
            data_bytes: Binary data to encode

        Returns:
            Base64 encoded ASCII string
        """
        if not isinstance(data_bytes, bytes):
            raise TypeError("Daten müssen vom Typ 'bytes' sein")

        encoded = base64.b64encode(data_bytes).decode("ascii")
        logger.debug(f"Encoded {len(data_bytes)} bytes to {len(encoded)} char string")
        return encoded

    @staticmethod
    def decode_base64(data_str: str) -> bytes:
        """
        Decode base64 string to bytes.

        Args:
            data_str: Base64 encoded string

        Returns:
            Decoded binary data

        Raises:
            ValueError: If string is not valid base64
        """
        if not isinstance(data_str, str):
            raise TypeError("Daten müssen vom Typ 'str' sein")

        try:
            decoded = base64.b64decode(data_str)
            logger.debug(f"Decoded {len(data_str)} char string to {len(decoded)} bytes")
            return decoded
        except Exception as e:
            logger.error(f"Base64 decoding failed: {e}")
            raise ValueError(f"Ungültiger Base64 String: {e}")


def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Timing-safe string/bytes comparison.

    Args:
        a: First value
        b: Second value

    Returns:
        True if equal, False otherwise

    Note:
        Use this for comparing passwords or tokens to prevent timing attacks
    """
    if type(a) != type(b):
        return False

    if isinstance(a, str):
        a = a.encode('utf-8')
        b = b.encode('utf-8')

    return nacl.utils.bytes_eq(a, b)


if __name__ == '__main__':
    # Test cryptography functions
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("Testing CryptoUtils")

    password = "test_password_1234"
    plaintext = b"Secret message for encryption test"

    logger.info(f"Original data: {plaintext}")

    # Generate salt and derive key
    salt = CryptoUtils.generate_salt()
    key = CryptoUtils.derive_key(password, salt)
    logger.info(f"Salt (base64): {CryptoUtils.encode_base64(salt)}")

    # Encrypt
    encrypted = CryptoUtils.encrypt(plaintext, key)
    logger.info(f"Encrypted: {CryptoUtils.encode_base64(encrypted)}")

    # Decrypt with same key
    key2 = CryptoUtils.derive_key(password, salt)
    decrypted = CryptoUtils.decrypt(encrypted, key2)
    logger.info(f"Decrypted: {decrypted}")

    # Verify
    if plaintext == decrypted:
        logger.info("✓ Encryption/Decryption successful!")
    else:
        logger.error("✗ Encryption/Decryption failed!")

    # Test wrong password
    try:
        wrong_key = CryptoUtils.derive_key("wrong_password", salt)
        CryptoUtils.decrypt(encrypted, wrong_key)
        logger.error("✗ Should have failed with wrong password!")
    except nacl.exceptions.CryptoError:
        logger.info("✓ Correctly rejected wrong password")
