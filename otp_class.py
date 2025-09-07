import base64
import cv2
import json
import logging
import os
import pyotp
import time
import datetime

import crypt_utils

logger = logging.getLogger(__name__)

class QRCodeNotFoundError(Exception):
    pass

class OtpClass:
    def __init__(self):
        logger.info("init otp class")
        # init variables
        self.config_filename = False
        self.data = {}
        self.decrypted = {}
        self.totp_objects = {}
        # read config and update variables
        self.read_config()
        if not self.data.get("salt", ""):
            salt = base64.b64encode(crypt_utils.CryptoUtils.generate_salt()).decode("ascii")
            self.data.update({"salt": salt})
        self.key = False
        self.__decrypt()

    def use_password(self, password):
        logger.info("set password")
        salt = base64.b64decode(self.data.get("salt", ""))
        self.key = crypt_utils.CryptoUtils.derive_key(password, salt)
        self.__decrypt()

    def __decrypt(self):
        logger.debug("start decrypting encrypt data")
        if self.key and self.data.get("encrypted", ""):
            try:
                encrypted = base64.b64decode(self.data.get("encrypted", ""))
                text_to_load = crypt_utils.CryptoUtils.decrypt(encrypted, self.key)
                self.decrypted = json.loads(text_to_load)
            except:
                raise TypeError("password incorrect")
            print(self.decrypted)
            self.__gen_otp_uri()

    def read_config(self):
        logger.info("read config")
        home_dir = os.path.expanduser("~")
        if os.name in ["nt", "windows"]:
            home_dir = os.path.join(home_dir, "AppData\\Local\\ThaOTP")
        else:
            home_dir = os.path.join(home_dir, ".config/ThaOTP")
        if not os.path.exists(home_dir):
            os.makedirs(home_dir)
        self.config_filename = os.path.join(home_dir, "config.json")
        logger.debug("open {}".format(self.config_filename))
        try:
            with open(self.config_filename, "r", encoding="utf-8") as config_file:
                data = json.load(config_file)
        except IOError as err:
            logger.warning("Oops, error: {}".format(err))
            data = {}
        self.data = data
        logger.debug(self.data)

    def write_config(self):
        logger.info("writing logs")
        if self.decrypted:
            text_to_log = json.dumps(self.decrypted)
            print(text_to_log)
            if self.key:
                encrypted = crypt_utils.CryptoUtils.encrypt(text_to_log.encode("utf-8"), self.key)
                print(encrypted)
                text_to_log = base64.b64encode(encrypted).decode("ascii")
                print(text_to_log)
            self.data.update({"encrypted": text_to_log})
            print(self.data)
        try:
            with open(self.config_filename, "w", encoding="utf-8") as config_file:
                json.dump(self.data, config_file, indent=4)
        except Exception as e:
            logger.error("writing config to file error: {}".format(e))

    def add_uri(self, uri, date=time.time()):
        logger.debug("add uri: {}".format(uri))
        if uri not in self.decrypted and self.key:
            logger.debug("add uri: {} - date: {}".format(uri, date))
            self.decrypted.update({uri: {"date": date}})
            self.totp_objects.update({uri: pyotp.parse_uri(uri)})

    def __gen_otp_uri(self):
        logger.debug("gen otp for all uris from {}".format(self.decrypted))
        if self.decrypted:
            for uri in self.decrypted.keys():
                logger.debug("gen otp for uri {}".format(uri))
                self.totp_objects.update({uri: pyotp.parse_uri(uri)})

    def gen_otp_number(self, uri, date=time.time()):
        logger.debug("gen one time number for otp uri: {}".format(uri))
        if self.totp_objects.get(uri, False):
            number = self.totp_objects.get(uri).at(date)
            return number
        return -1

    def interval(self, uri):
        if self.totp_objects.get(uri, False):
            return self.totp_objects.get(uri).interval
        else:
            return 0

    def created(self, uri):
        if self.decrypted.get(uri, False):
            return self.decrypted.get(uri, {}).get("date", 0)
        else:
            return 0

    def get_uri(self):
        return self.totp_objects.keys()

    def status(self):
        if self.key or "encrypted" not in self.data.keys():
            return True
        return False


def read_uri_from_qr_image(filepath: str) -> str:
    """Liest ein QR-Code-Bild und gibt den enthaltenen Text zurück."""
    image = cv2.imread(filepath)
    if image is None:
        raise cv2.error("Bild konnte nicht gelesen werden.")  # OpenCV gibt None zurück, nicht immer einen Error

    detector = cv2.QRCodeDetector()
    decoded_text, _, _ = detector.detectAndDecode(image)

    if not decoded_text:
        raise QRCodeNotFoundError("Im Bild wurde kein QR-Code gefunden.")

    return decoded_text


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger.info("moin")

    test = OtpClass()
    test.use_password("test")
    filename = "Download.png"
    uri = read_uri_from_qr_image(filename)
    t1 = 1755068753.2957523
    #uri = ""
    test.add_uri(uri, t1)
    #test.write_config()
    #number = test.gen_otp_number(uri=uri)
    #logger.info("one time number for uri: {} is {}".format(uri, number))
    uris = test.get_uri()
    for uri in uris:
        logger.info("one time number for uri: {} is {}".format(uri, test.gen_otp_number(uri, t1)))
        logger.info("one time number for uri: {} is {}".format(uri, test.gen_otp_number(uri)))
