import logging
import time
import tkinter
from tkinter import filedialog, messagebox

import exceptions
import service

logger = logging.getLogger(__name__)


class AddOtp(tkinter.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        logger.info("add otp entry display window")
        self.title("Add Otp Entry")
        self.geometry(self.master.otp.raw_config_data.get("otp_add_geometry", None))

        tkinter.Label(self, text="Hi").grid(row=0, column=0, padx=5, pady=5)

        self.label_filename = tkinter.Label(self, text="Filename:")
        self.label_filename.grid(row=1, column=0, padx=5, pady=5, sticky=tkinter.E)
        self.entry_filename = tkinter.Entry(self, width=30)
        self.entry_filename.grid(row=1, column=1, padx=5, pady=5, sticky="nw")
        self.button_filemanager = tkinter.Button(self, text="Filemanager", command=self.click_button_filemanager)
        self.button_filemanager.grid(row=1, column=2)

        self.button_read = tkinter.Button(self, text="read qr", command=self.on_click_read_qr)
        self.button_read.grid(row=2, column=1)

        self.label_text = tkinter.Label(self, text="OTP URL:")
        self.label_text.grid(row=3, column=0, padx=5, pady=5, sticky=tkinter.E)
        self.entry_text = tkinter.Entry(self, width=30)
        self.entry_text.grid(row=3, column=1, padx=5, pady=5)

        self.button_add = tkinter.Button(self, text="add otp", command=self.on_click_add)
        self.button_add.grid(row=4, column=1)

        self.transient(master)
        self.grab_set()

    def click_button_filemanager(self):
        logger.debug("open filemanager to chose file")
        files = [("PNG files", "*.png"), ("SVG files", "*.svg")]
        file_path = filedialog.askopenfilename(filetypes=files)
        if file_path:
            self.entry_filename.delete(0, tkinter.END)
            self.entry_filename.insert(0, str(file_path))

    def on_click_read_qr(self):
        logger.debug("read qr code")
        if self.entry_filename.get():
            text = service.read_uri_from_qr_image(self.entry_filename.get())
            self.entry_text.delete(0, tkinter.END)
            self.entry_text.insert(0, str(text))

    def on_click_add(self):
        logger.debug("click add")
        try:
            self.master.otp.add_uri(self.entry_text.get(), time.time())
        except exceptions.UriError as err:
            tkinter.messagebox.showerror("error", f"uri konnte nicht hinzugefügt werden: {err}")
        self.master.otp.save()
        self.master.update_rows()
        self.destroy()

class ChangePw(tkinter.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        logger.info("change pw")
        self.title("Change PW")
        self.geometry(self.master.otp.raw_config_data.get("pw_change_geometry", None))

        tkinter.Label(self, text="set new pw").grid(row=0, column=0)

        self.label_password_1 = tkinter.Label(self, text="Password 1:")
        self.label_password_1.grid(row=1, column=0, padx=5, pady=5)
        self.entry_password_1 = tkinter.Entry(self, width=21, show='*')
        self.entry_password_1.grid(row=1, column=1, padx=5, pady=5, sticky="nw")

        self.label_password_2 = tkinter.Label(self, text="Password 2:")
        self.label_password_2.grid(row=2, column=0, padx=5, pady=5)
        self.entry_password_2 = tkinter.Entry(self, width=21, show='*')
        self.entry_password_2.grid(row=2, column=1, padx=5, pady=5, sticky="nw")

        tkinter.Button(self, text="set new pw", command=self.on_click_set).grid(row=3, column=1, padx=5, pady=5)

        self.transient(master)
        self.grab_set()

    def on_click_set(self):
        logger.info("set new pw")
        if self.entry_password_1.get() != self.entry_password_2.get():
            messagebox.showinfo("Passwörter stimmen nicht überein")
        else:
            if tkinter.messagebox.askyesno("PW Änderung bestätigen", "Möchtest du das Passwort wirklich ändern"):
                self.master.otp.set_new_password(self.entry_password_1.get())
                self.master.otp.save()
                self.destroy()
