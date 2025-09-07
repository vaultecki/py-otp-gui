import tkinter
import tkinter.messagebox
import logging
import time

import otp_class
import exceptions
import extra_windows

logger = logging.getLogger(__name__)


class PasswordWindow(tkinter.Toplevel):
    def __init__(self, master,  on_success):
        super().__init__(master)
        logger.info("open password input display window")
        #Set the geometry of frame
        self.geometry(self.master.otp.raw_config_data.get("pw_enter_geometry", "600x250"))
        self.title("Password Window")
        self.on_success = on_success

        #Create a text label
        tkinter.Label(self, text="Enter the Password for saved otp").pack(pady=20)
        #Create Entry Widget for password
        self.password_entry = tkinter.Entry(self, show="*",width=20)
        self.password_entry.pack()
        #button
        tkinter.Button(self, text="Try PW", command=self.send_password).pack(pady=20)

        self.transient(master)
        self.grab_set()

    def send_password(self):
        logger.info("password button clicked")
        try:
            self.master.otp.unlock_with_password(self.password_entry.get())  # Umbenannte Methode
            self.on_success()
            self.master.otp.raw_config_data.update({"pw_enter_geometry": self.geometry()})
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
        self.otp_numbers = {}
        self.geometry(self.otp.raw_config_data.get("main_geometry", None))

        # --- Statischer Frame für die Kontroll-Buttons ---
        control_frame = tkinter.Frame(self)
        control_frame.pack(side="bottom", fill="x", pady=10)

        self.add_button_change_pw = tkinter.Button(control_frame, text="Change Password", command=self.on_click_pw_change)
        self.add_button_change_pw.pack(side="left", padx=5)

        self.add_button_txt = tkinter.Button(control_frame, text="Add OTP URL", command=self.on_click_add)
        self.add_button_txt.pack(side="right", padx=5)

        # --- Frame für die dynamische OTP-Liste ---
        self.otp_list_frame = tkinter.Frame(self)
        self.otp_list_frame.pack(side="top", fill="both", expand=True)

        if not self.otp.is_unlocked:
            logger.info("ask for password")
            PasswordWindow(self, on_success=self.update_rows)

    def create_row(self, uri:str, row_index:int):
        logger.debug(f"add row {row_index} for uri {uri}")
        # Wichtig: Die Widgets dem otp_list_frame hinzufügen, nicht self!
        parent_frame = self.otp_list_frame
        number_str = tkinter.StringVar(parent_frame, self.otp.gen_otp_number(uri))
        self.otp_numbers.update({uri: number_str})
        tkinter.Entry(parent_frame, textvariable=number_str, state="readonly", width=8).grid(row=row_index, column=0)
        uri_string = tkinter.StringVar(parent_frame, uri)
        tkinter.Entry(parent_frame, textvariable=uri_string, state="readonly", width=80).grid(row=row_index, column=1)
        time_str = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime(self.otp.created(uri)))
        tkinter.Label(parent_frame, text="created {}".format(time_str)).grid(row=row_index, column=2)
        tkinter.Button(parent_frame, text="delete", command=lambda u=uri: self.delete(u)).grid(row=row_index, column=3)

    def _update_all_otps(self):
        logger.info(f"it's time {time.time()}")
        for uri, number in self.otp_numbers.items():
            logger.debug(f"time to update uri {uri} and number {number.get()}")
            number.set(self.otp.gen_otp_number(uri, time.time()))
        self.after(5000, self._update_all_otps)

    def update_rows(self):
        if not self.otp.is_unlocked:
            return
        # Lösche alte Einträge, falls vorhanden (wichtig bei erneutem Aufruf)
        for widget in self.otp_list_frame.winfo_children():
            widget.destroy()
        # Erstelle neue Einträge
        for index, uri in enumerate(self.otp.get_uri()):
            self.create_row(uri, index)  # create_row muss jetzt in self.otp_list_frame zeichnen
        # Die Buttons müssen nicht mehr neu gezeichnet werden!
        self._update_all_otps()
        self.otp.raw_config_data.update({"main_geometry": self.geometry()})

    def delete(self, uri_to_delete):
        logger.info(f"Attempting to delete {uri_to_delete}")
        # Bestätigungsdialog anzeigen
        if tkinter.messagebox.askyesno("Löschen bestätigen", f"Möchtest du '{uri_to_delete}' wirklich löschen?"):
            self.otp.delete_uri(uri_to_delete)
            self.otp.save()
            self.update_rows()

    def on_click_add(self):
        logger.info("on click add")
        if self.otp.is_unlocked:
            extra_windows.AddOtp(self)

    def on_click_pw_change(self):
        logger.info(f"change password for OTP")
        if self.otp.is_unlocked:
            extra_windows.ChangePw(self)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger.info("moin")

    app = App()
    app.mainloop()
