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
        # init variables
        self.config_filename = self._get_config_file_path()
        self.key = None
        self.is_unlocked = False
        self.decrypted_data = {}
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
        logger.debug("start decrypting encrypt data")
        if self.raw_config_data.get("encrypted", "") and self.is_unlocked:
            try:
                text_to_load = self.raw_config_data.get("encrypted", "")
                self.decrypted_data = json.loads(text_to_load)
            except (json.JSONDecodeError, TypeError):
                logger.info("laden ohne passwort schlug fehl")
        if self.key and self.raw_config_data.get("encrypted", "") and not self.is_unlocked:
            try:
                encrypted = crypt_utils.CryptoUtils.decode_base64(self.raw_config_data.get("encrypted", ""))
                text_to_load = crypt_utils.CryptoUtils.decrypt(encrypted, self.key)
                self.decrypted_data = json.loads(text_to_load)
            except nacl.exceptions.CryptoError:
                # Gib dem Aufrufer eine klare Rückmeldung
                raise exceptions.InvalidPasswordError("Entschlüsselung fehlgeschlagen. Wahrscheinlich ist das Passwort falsch.")
            except (json.JSONDecodeError, TypeError):
                raise exceptions.ConfigFileError("Die Konfigurationsdatei scheint beschädigt zu sein.")
            self.is_unlocked = True

    @staticmethod
    def _get_config_file_path():
        logger.info("create config file name")
        home_dir = os.path.expanduser("~")
        if os.name in ["nt", "windows"]:
            home_dir = os.path.join(home_dir, "AppData\\Local\\ThaOTP")
        else:
            home_dir = os.path.join(home_dir, ".config/ThaOTP")
        if not os.path.exists(home_dir):
            os.makedirs(home_dir)
        return os.path.join(home_dir, "config.json")

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
            text_to_log = json.dumps(self.decrypted_data)
            if self.key:
                encrypted = crypt_utils.CryptoUtils.encrypt(text_to_log.encode("utf-8"), self.key)
                text_to_log = crypt_utils.CryptoUtils.encode_base64(encrypted)
            self.raw_config_data.update({"encrypted": text_to_log})
        try:
            with open(self.config_filename, "w", encoding="utf-8") as config_file:
                json.dump(self.raw_config_data, config_file, indent=4)
        except Exception as e:
            logger.error("writing config to file error: {}".format(e))

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
