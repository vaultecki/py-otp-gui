import cv2
import json
import logging
import os
import pyotp
import time
import datetime
# import from project
import helper

logger = logging.getLogger(__name__)

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
        self.enc_helper = helper.EncHelper(salt=self.data.get("salt",""))
        self.data.update({"salt": self.enc_helper.get_salt()})
        self.__decrypt()

    def use_password(self, password):
        logger.info("set password")
        try:
            self.enc_helper.set_password(password)
        except:
            logger.info("error setting password")
            return
        self.__decrypt()

    def __decrypt(self):
        logger.debug("start decrypting encrypt data")
        if self.enc_helper.status():
            try:
                self.decrypted = json.loads(self.enc_helper.decrypt(self.data.get("encrypted", "")))
            except:
                self.decrypted = {}
            print(self.decrypted)
            self.__gen_otp_uri()

    def read_config(self):
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
        if self.enc_helper.status():
            logger.info("encrypt uris {}".format(json.dumps(self.decrypted)))
            self.data.update({"encrypted": self.enc_helper.encrypt(json.dumps(self.decrypted))})
        try:
            with open(self.config_filename, "w", encoding="utf-8") as config_file:
                json.dump(self.data, config_file, indent=4)
        except Exception as e:
            logger.error("writing config to file error: {}".format(e))

    def add_uri_from_qrcode(self, filename):
        image = cv2.imread(filename)
        # initialize the cv2 QRCode detector
        detector = cv2.QRCodeDetector()
        # detect and decode
        uri, vertices_array, binary_qrcode = detector.detectAndDecode(image)
        if vertices_array is None:
            logger.error("There was some error")
            return
        logger.debug("QRCode data: {}".format(uri))
        self.add_uri(uri)

    def add_uri(self, uri, date=time.time()):
        logger.debug("add uri: {}".format(uri))
        if uri not in self.decrypted and self.enc_helper.status():
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
        return self.enc_helper.status()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger.info("moin")

    test = OtpClass()
    test.use_password("test")
    # filename = "Download.png"
    # test.add_uri_from_qrcode(filename)
    t1 = 1755068753.2957523
    #uri = "..."
    #test.add_uri(uri, t1)
    #test.write_config()
    #number = test.gen_otp_number(uri=uri)
    #logger.info("one time number for uri: {} is {}".format(uri, number))
    uris = test.get_uri()
    for uri in uris:
        logger.info("one time number for uri: {} is {}".format(uri, test.gen_otp_number(uri, t1)))
        logger.info("one time number for uri: {} is {}".format(uri, test.gen_otp_number(uri)))
