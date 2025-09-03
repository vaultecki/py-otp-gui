import tkinter
import logging
import os
import PySignal
import threading
import time
from PIL import Image

# import from project
import otp_class

logger = logging.getLogger(__name__)


class PasswordWindow(tkinter.Toplevel):
    pw_entered = PySignal.ClassSignal()
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        logger.info("open qr code display window")
        #Set the geometry of frame
        self.geometry("600x250")
        self.title("Password Window")
        #Create a text label
        tkinter.Label(self, text="Enter the Password for saved otp", font=('Helvetica',20)).pack(pady=20)

        #Create Entry Widget for password
        self.password_entry = tkinter.Entry(self, show="*",width=20)
        self.password_entry.pack()

        #Create a button to close the window
        tkinter.Button(self, text="Try PW", font=('Helvetica bold', 10), command=self.send_password).pack(pady=20)

    def run(self):
        self.transient(self.master)
        self.grab_set()

    def send_password(self):
        self.pw_entered.emit(self.password_entry.get())

    def close(self, value):
        if not value:
            print("try to close window")
            self.destroy()
            self.update()
        return


class App(tkinter.Tk):
    no_password = PySignal.ClassSignal()
    def __init__(self):
        super().__init__()

        self.title("Py OTP GUI")

        self.otp = otp_class.OtpClass()

        self.i = 0
        self.stop = False
        self.otp_numbers = []
        self.timers = []
        self.password_window = PasswordWindow(self)
        self.password_window.pw_entered.connect(self.pw_received)
        self.no_password.connect(self.password_window.close)

        self.add_button_txt = tkinter.Button(self, text="add from string")
        self.add_button_txt.grid(row=0, column=0)
        self.add_button_qr = tkinter.Button(self, text="add from qr")
        self.add_button_qr.grid(row=0, column=1)

        if not self.otp.status():
            self.ask_for_password()

    def create_row(self, uri):
        number_str = tkinter.StringVar(self, self.otp.gen_otp_number(uri))
        self.otp_numbers.append(number_str)
        tkinter.Entry(self, textvariable=number_str, state="readonly", width=8).grid(row=self.i, column=0)
        uri_string = tkinter.StringVar(self, uri)
        tkinter.Entry(self, textvariable=uri_string, state="readonly", width=80).grid(row=self.i, column=1)
        time_str = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime(self.otp.created(uri)))
        tkinter.Label(self, text="created {}".format(time_str)).grid(row=self.i, column=2)
        tkinter.Button(self, text="delete", command=self.delete).grid(row=self.i, column=3)
        i = self.i
        self.i = self.i + 1
        interval = self.otp.interval(uri)-2
        t = threading.Thread(target=self.update_number, args=(interval, i, uri))
        self.timers.append(t)
        t.start()
        return

    def update_number(self, interval, i, uri):
        if i < len(self.otp_numbers):
            while self.timers and not self.stop:
                time.sleep(interval)
                print(f"it's time {time.time()}")
                print(self.otp_numbers[i].get())
                self.otp_numbers[i].set(self.otp.gen_otp_number(uri, time.time()))

    def ask_for_password(self):
        logger.info("ask for password")
        self.password_window.run()
        return

    def pw_received(self, password):
        # for testing purposes - remove later
        self.otp.use_password(password)
        print(f"otp status is {self.otp.status()}")
        if not self.otp.status():
            self.no_password.emit(True)
            return

        self.no_password.emit(False)

        for uri in self.otp.get_uri():
            self.create_row(uri)

        self.add_button_txt.grid(row=self.i, column=1)
        self.add_button_qr.grid(row=self.i, column=2)

    def delete(self):
        logger.info("delete")

    def on_closing(self):
        self.stop = True
        for t in self.timers:
            t.join(timeout=0.5)
        self.destroy()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger.info("moin")

    app = App()
    app.mainloop()
