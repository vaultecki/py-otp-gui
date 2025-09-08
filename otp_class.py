import json
import logging
import os
from configparser import ParsingError

import nacl.exceptions
import pyotp
import time

import crypt_utils
import exceptions

logger = logging.getLogger(__name__)


class OtpClass:
    def __init__(self):
        logger.info("init otp class")
        # prepare paths
        self.config_filename = self._get_config_file_filename()
        self._ensure_config_directory_exists()
        # init rest of the variables
        self.key = None
        self.is_unlocked = False
        self.decrypted_data = {}
        # read data from config file
        self.raw_config_data = self._read_config()

        # Wenn die Konfiguration leer ist, erstelle eine neue.
        if not self.raw_config_data:
            self.is_unlocked = True  # Ein neuer Tresor ist sofort entsperrt
            self.decrypted_data = {}  # Explizit initialisieren
            self._create_new_salt()
        else:
            # Ein bestehender Tresor muss entsperrt werden
            self.is_unlocked = False

    def _create_new_salt(self):
        """Erzeugt ein neues Salt für einen neuen Tresor."""
        salt = crypt_utils.CryptoUtils.encode_base64(crypt_utils.CryptoUtils.generate_salt())
        self.raw_config_data.update({"salt": salt})

    def unlock_with_password(self, password):
        logger.info("set password")
        salt = crypt_utils.CryptoUtils.decode_base64(self.raw_config_data.get("salt", ""))
        self.key = crypt_utils.CryptoUtils.derive_key(password, salt)
        self._decrypt()

    def set_new_password(self, password):
        logger.info("set password")
        if self.is_unlocked:
            salt = crypt_utils.CryptoUtils.decode_base64(self.raw_config_data.get("salt", ""))
            self.key = crypt_utils.CryptoUtils.derive_key(password, salt)

    def _decrypt(self):
        logger.debug("Attempting to decrypt data with provided key.")
        # Es gibt nichts zu tun, wenn kein Schlüssel oder keine Daten vorhanden sind.
        if not self.key or not self.raw_config_data.get("encrypted", ""):
            return

        try:
            encrypted = crypt_utils.CryptoUtils.decode_base64(self.raw_config_data.get("encrypted", ""))
            text_to_load = crypt_utils.CryptoUtils.decrypt(encrypted, self.key)
            self.decrypted_data = json.loads(text_to_load)
            # Nur bei Erfolg wird der Tresor als entsperrt markiert.
            self.is_unlocked = True
            logger.info("Decryption successful. Vault is unlocked.")
        except nacl.exceptions.CryptoError:
            raise exceptions.InvalidPasswordError(
                "Entschlüsselung fehlgeschlagen. Wahrscheinlich ist das Passwort falsch.")
        except (json.JSONDecodeError, TypeError):
            raise exceptions.ConfigFileError("Die Konfigurationsdatei scheint beschädigt zu sein.")

    @staticmethod
    def _get_config_file_path():
        logger.info("create config file name")
        home_dir = os.path.expanduser("~")
        if os.name in ["nt", "windows"]:
            home_dir = os.path.join(home_dir, "AppData\\Local\\ThaOTP")
        else:
            home_dir = os.path.join(home_dir, ".config/ThaOTP")
        return home_dir

    def _get_config_file_filename(self):
        home_dir = self._get_config_file_path()
        return os.path.join(home_dir, "config.json")

    def _ensure_config_directory_exists(self):
        home_dir = self._get_config_file_path()
        if not os.path.exists(home_dir):
            os.makedirs(home_dir)

    def _read_config(self):
        logger.debug("open {}".format(self.config_filename))
        try:
            with open(self.config_filename, "r", encoding="utf-8") as config_file:
                return json.load(config_file)
        except (IOError, json.JSONDecodeError) as err:
            logger.warning(f"Could not read or parse config file: {err}. Assuming new configuration.")
            # Gib None oder ein leeres Dict zurück, um den "nicht gefunden"-Fall zu signalisieren
            return {}

    def save(self):
        logger.info("writing logs")
        if self.decrypted_data:
            json_string = json.dumps(self.decrypted_data)
            encrypted_string = self._encrypt_data(json_string)
            self.raw_config_data.update({"encrypted": encrypted_string})

        try:
            with open(self.config_filename, "w", encoding="utf-8") as config_file:
                json.dump(self.raw_config_data, config_file, indent=4)
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
            self.decrypted_data.update({uri: {"date": date}})

    def gen_otp_number(self, uri, date=time.time()):
        logger.debug("gen one time number for otp uri: {}".format(uri))
        if uri in self.decrypted_data:
            totp = pyotp.parse_uri(uri)
            return totp.at(date)
        return -1

    def created(self, uri):
        if self.decrypted_data.get(uri, False):
            return self.decrypted_data.get(uri, {}).get("date", 0)
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
