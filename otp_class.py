import json
import logging
import os
from dataclasses import dataclass, asdict
import nacl.exceptions
import pyotp
import time

import config_manager
import crypt_utils
import exceptions

logger = logging.getLogger(__name__)

@dataclass
class OtpEntry:
    uri: str
    created_at: float = time.time()

class OtpClass:
    def __init__(self):
        logger.info("init otp class")
        self.config = config_manager.ConfigManager()
        # init rest of the variables
        self.key = None
        self.is_unlocked = False
        self.decrypted_data = {}
        self.decrypted_data = {}
        # Logik zum Initialisieren des Tresors (Salt, etc.)
        self._initialize_vault()

    def _initialize_vault(self):
        logger.debug("_initialize_vault")
        if not self.config.get("salt"):
            logger.debug("create new vault - salt")
            self.is_unlocked = True
            salt = crypt_utils.CryptoUtils.encode_base64(crypt_utils.CryptoUtils.generate_salt())
            self.config.set("salt", salt)
        else:
            logger.debug("vault already exists")
            self.is_unlocked = False

    def unlock_with_password(self, password):
        logger.info("set password")
        salt = crypt_utils.CryptoUtils.decode_base64(self.config.get("salt"))
        self.key = crypt_utils.CryptoUtils.derive_key(password, salt)
        self._decrypt()

    def set_new_password(self, password):
        logger.info("try to set new password")
        if self.is_unlocked:
            logger.info("setting new password")
            salt = crypt_utils.CryptoUtils.decode_base64(self.config.get("salt"))
            self.key = crypt_utils.CryptoUtils.derive_key(password, salt)

    def _decrypt(self):
        logger.debug("Attempting to decrypt data with provided key.")
        # Es gibt nichts zu tun, wenn kein Schlüssel oder keine Daten vorhanden sind.
        if not self.key or not self.config.get("encrypted"):
            return

        try:
            encrypted = crypt_utils.CryptoUtils.decode_base64(self.config.get("encrypted"))
            text_to_load = crypt_utils.CryptoUtils.decrypt(encrypted, self.key)
            # Lade die rohen Dictionary-Daten
            raw_data = json.loads(text_to_load)

            # Wandle die Dictionaries direkt in OtpEntry-Objekte um
            self.decrypted_data = {
                uri: OtpEntry(**data) for uri, data in raw_data.items()
            }

            self.is_unlocked = True
            logger.info("Decryption successful. Vault is unlocked.")

        except nacl.exceptions.CryptoError:
            raise exceptions.InvalidPasswordError(
                "Entschlüsselung fehlgeschlagen. Wahrscheinlich ist das Passwort falsch.")
        except (json.JSONDecodeError, TypeError):
            raise exceptions.ConfigFileError("Die Konfigurationsdatei scheint beschädigt zu sein.")

    def save(self):
        logger.info("writing logs")
        if self.decrypted_data:
            data_to_save = {uri: asdict(entry) for uri, entry in self.decrypted_data.items()}
            json_string = json.dumps(data_to_save)
            encrypted_string = self._encrypt_data(json_string)
            self.config.set("encrypted", encrypted_string)

        try:
            self.config.save()
        except IOError as e:
            logger.error(f"Error writing config to file: {e}")

    def _encrypt_data(self, data_to_encrypt: str) -> str:
        """Verschlüsselt die Daten, falls ein Schlüssel vorhanden ist."""
        if self.key:
            encrypted_bytes = crypt_utils.CryptoUtils.encrypt(data_to_encrypt.encode("utf-8"), self.key)
            return crypt_utils.CryptoUtils.encode_base64(encrypted_bytes)
        # Gib die Daten unverschlüsselt zurück, wenn kein Schlüssel gesetzt ist
        return data_to_encrypt

    def add_uri(self, uri, date=time.time()):
        logger.debug("add uri: {}".format(uri))
        if uri not in self.decrypted_data and self.is_unlocked and uri:
            logger.debug("add uri: {} - date: {}".format(uri, date))
            try:
                pyotp.parse_uri(uri)
            except Exception as err:
                raise exceptions.UriError(f"Could not read or parse uri: {err}.")
            entry = OtpEntry(uri=uri)
            # decrypted_data würde jetzt OtpEntry-Objekte speichern
            self.decrypted_data[uri] = entry

    def gen_otp_number(self, uri, date=time.time()):
        logger.debug("gen one time number for otp uri: {}".format(uri))
        if uri in self.decrypted_data:
            totp = pyotp.parse_uri(uri)
            return totp.at(date)
        return -1

    def created(self, uri):
        if self.decrypted_data:
            return self.decrypted_data.get(uri, OtpEntry("no_entry", 0)).created_at
        else:
            return 0

    def get_uri(self):
        return self.decrypted_data.keys()

    def delete_uri(self, uri: str):
        logger.debug(f"Deleting uri: {uri}")
        if uri in self.decrypted_data:
            del self.decrypted_data[uri]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger.info("moin")

    test = OtpClass()
    test.unlock_with_password("test")
    filename = "Download.png"
    t1 = 1755068753.2957523
    #url = ""
    #test.add_uri(uri, t1)
    #test.save()
    #number = test.gen_otp_number(uri=uri)
    #logger.info("one time number for uri: {} is {}".format(uri, number))
    urls = test.get_uri()
    #print(urls)
    #test.delete_uri("")
    #urls = test.get_uri()
    #print(urls)
    for url in urls:
        logger.info("one time number for uri: {} is {}".format(url, test.gen_otp_number(url, t1)))
        logger.info("one time number for uri: {} is {}".format(url, test.gen_otp_number(url)))
    #test.save()
