import tkinter
import tkinter.messagebox
import logging
import time
import PySignal

import otp_class
import exceptions

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
        logger.info("password button clicked")
        try:
            self.master.otp.unlock_with_password(self.password_entry.get())  # Umbenannte Methode
            self.pw_entered.emit()
            self.destroy()
        except exceptions.InvalidPasswordError as e:
            # Zeige dem Benutzer eine Fehlermeldung
            tkinter.messagebox.showerror("Fehler", str(e))
        except Exception as e:
            tkinter.messagebox.showerror("Unerwarteter Fehler", f"Ein Fehler ist aufgetreten: {e}")


class App(tkinter.Tk):
    def __init__(self):
        super().__init__()
        self.title("Py OTP GUI")

        self.otp = otp_class.OtpClass()

        self.i = 0
        self.stop = False
        self.otp_numbers = {}
        self.password_window = PasswordWindow(self)
        self.password_window.pw_entered.connect(self.update_rows)

        self.add_button_txt = tkinter.Button(self, text="add from string")
        self.add_button_txt.grid(row=0, column=0)
        self.add_button_qr = tkinter.Button(self, text="add from qr")
        self.add_button_qr.grid(row=0, column=1)

        if not self.otp.is_unlocked:
            self.ask_for_password()

    def create_row(self, uri):
        number_str = tkinter.StringVar(self, self.otp.gen_otp_number(uri))
        self.otp_numbers.update({uri: number_str})
        tkinter.Entry(self, textvariable=number_str, state="readonly", width=8).grid(row=self.i, column=0)
        uri_string = tkinter.StringVar(self, uri)
        tkinter.Entry(self, textvariable=uri_string, state="readonly", width=80).grid(row=self.i, column=1)
        time_str = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime(self.otp.created(uri)))
        tkinter.Label(self, text="created {}".format(time_str)).grid(row=self.i, column=2)
        tkinter.Button(self, text="delete", command=self.delete).grid(row=self.i, column=3)
        self.i = self.i + 1

    def _update_all_otps(self):
        print(f"it's time {time.time()}")
        for uri, number in self.otp_numbers.items():
            print(f"time to update uri {uri} and number {number.get()}")
            number.set(self.otp.gen_otp_number(uri, time.time()))
        self.after(5000, self._update_all_otps)

    def ask_for_password(self):
        logger.info("ask for password")
        self.password_window.run()
        return

    def update_rows(self):
        # for testing purposes - remove later
        if not self.otp.is_unlocked:
            return
        print(f"otp status is {self.otp.is_unlocked}")
        for uri in self.otp.get_uri():
            self.create_row(uri)
        self.add_button_txt.grid(row=self.i, column=1)
        self.add_button_qr.grid(row=self.i, column=2)
        self.add_button_change_pw = tkinter.Button(self, text="change password")
        self.add_button_change_pw.grid(row=self.i, column=0)

        self._update_all_otps()

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
