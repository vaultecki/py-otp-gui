import json
import logging
import os
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
        self.totp_objects = {}
        self.data = self._read_config()

        # Wenn die Konfiguration leer ist, erstelle eine neue.
        if not self.data:
            self.is_unlocked = True  # Ein neuer Tresor ist sofort entsperrt
            self.decrypted_data = {}  # Explizit initialisieren
            self._create_new_salt()
        else:
            # Ein bestehender Tresor muss entsperrt werden
            self.is_unlocked = False

    def _create_new_salt(self):
        """Erzeugt ein neues Salt für einen neuen Tresor."""
        salt = crypt_utils.CryptoUtils.encode_base64(crypt_utils.CryptoUtils.generate_salt())
        self.data["salt"] = salt

    def unlock_with_password(self, password):
        logger.info("set password")
        salt = crypt_utils.CryptoUtils.decode_base64(self.data.get("salt", ""))
        self.key = crypt_utils.CryptoUtils.derive_key(password, salt)
        self._decrypt()

    def _decrypt(self):
        logger.debug("start decrypting encrypt data")
        if self.key and self.data.get("encrypted", ""):
            try:
                encrypted = crypt_utils.CryptoUtils.decode_base64(self.data.get("encrypted", ""))
                text_to_load = crypt_utils.CryptoUtils.decrypt(encrypted, self.key)
                self.decrypted_data = json.loads(text_to_load)
            except nacl.exceptions.CryptoError:
                # Gib dem Aufrufer eine klare Rückmeldung
                raise exceptions.InvalidPasswordError("Entschlüsselung fehlgeschlagen. Wahrscheinlich ist das Passwort falsch.")
            except (json.JSONDecodeError, TypeError):
                raise exceptions.ConfigFileError("Die Konfigurationsdatei scheint beschädigt zu sein.")
            self.is_unlocked = True
            self.__gen_otp_uri()

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

    def write_config(self):
        logger.info("writing logs")
        if self.decrypted_data:
            text_to_log = json.dumps(self.decrypted_data)
            if self.key:
                encrypted = crypt_utils.CryptoUtils.encrypt(text_to_log.encode("utf-8"), self.key)
                text_to_log = crypt_utils.CryptoUtils.encode_base64(encrypted)
            self.data.update({"encrypted": text_to_log})
        try:
            with open(self.config_filename, "w", encoding="utf-8") as config_file:
                json.dump(self.data, config_file, indent=4)
        except Exception as e:
            logger.error("writing config to file error: {}".format(e))

    def add_uri(self, uri, date=time.time()):
        logger.debug("add uri: {}".format(uri))
        if uri not in self.decrypted_data and self.key:
            logger.debug("add uri: {} - date: {}".format(uri, date))
            self.decrypted_data.update({uri: {"date": date}})
            self.totp_objects.update({uri: pyotp.parse_uri(uri)})

    def __gen_otp_uri(self):
        logger.debug("gen otp for all uris from {}".format(self.decrypted_data))
        if self.decrypted_data:
            for uri in self.decrypted_data.keys():
                logger.debug("gen otp for uri {}".format(uri))
                self.totp_objects.update({uri: pyotp.parse_uri(uri)})

    def gen_otp_number(self, uri, date=time.time()):
        logger.debug("gen one time number for otp uri: {}".format(uri))
        if self.totp_objects.get(uri, False):
            number = self.totp_objects.get(uri).at(date)
            return number
        return -1

    def created(self, uri):
        if self.decrypted_data.get(uri, False):
            return self.decrypted_data.get(uri, {}).get("date", 0)
        else:
            return 0

    def get_uri(self):
        return self.totp_objects.keys()

    def delete_uri(self, uri: str):
        logger.debug(f"Deleting uri: {uri}")
        # Sicher aus beiden Dictionaries entfernen
        if uri in self.decrypted_data:
            del self.decrypted_data[uri]
        if uri in self.totp_objects:
            del self.totp_objects[uri]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger.info("moin")

    test = OtpClass()
    test.unlock_with_password("test")
    filename = "Download.png"
    #uri = read_uri_from_qr_image(filename)
    t1 = 1755068753.2957523
    uri = ""
    #test.add_uri(uri, t1)
    #test.write_config()
    #number = test.gen_otp_number(uri=uri)
    #logger.info("one time number for uri: {} is {}".format(uri, number))
    uris = test.get_uri()
    for uri in uris:
        logger.info("one time number for uri: {} is {}".format(uri, test.gen_otp_number(uri, t1)))
        logger.info("one time number for uri: {} is {}".format(uri, test.gen_otp_number(uri)))
