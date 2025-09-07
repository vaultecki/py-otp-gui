import logging
import nacl.secret
import nacl.utils
import nacl.pwhash

logger = logging.getLogger(__name__)


class CryptoUtils:
    @staticmethod
    def generate_salt() -> bytes:
        logger.debug("generate salt")
        return nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES)

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Leitet einen sicheren Schlüssel aus Passwort und Salt ab."""
        logger.debug("derive key")
        password_bytes = password.encode("utf-8")
        kdf = nacl.pwhash.argon2i.kdf
        return kdf(nacl.secret.SecretBox.KEY_SIZE, password_bytes, salt)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """Verschlüsselt Daten mit einem gegebenen Schlüssel."""
        logger.debug("encrypt data")
        box = nacl.secret.SecretBox(key)
        return box.encrypt(data)

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """Entschlüsselt Daten mit einem gegebenen Schlüssel."""
        logger.debug("decrypt data")
        box = nacl.secret.SecretBox(key)
        return box.decrypt(encrypted_data)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger.info("main of helper.py")

    password = "moin"
    bytes_text = b"test 1234"
    logger.debug(f"plain data: {bytes_text}")

    salt = CryptoUtils.generate_salt()
    key = CryptoUtils.derive_key(password, salt)
    logger.debug(f"salt: {salt}")

    enc_msg = CryptoUtils.encrypt(bytes_text, key)
    logger.debug(f"encrypted data: {enc_msg}")

    key2 = CryptoUtils.derive_key(password, salt)
    dec_msg = CryptoUtils.decrypt(enc_msg, key2)
    logger.debug(f"decrypted data: {dec_msg}")
