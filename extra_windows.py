# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Extra Windows Module - Additional dialog windows for OTP Manager.

Contains dialogs for adding OTP entries, changing passwords, and displaying QR codes.
"""

import logging
import time
import tkinter
from tkinter import filedialog, messagebox

import exceptions
import service

logger = logging.getLogger(__name__)

# QR Generator import with fallback
try:
    import qr_generator

    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    logger.warning("qr_generator module not available - QR code features disabled")


class AddOtp(tkinter.Toplevel):
    """Dialog window for adding new OTP entries."""

    def __init__(self, master):
        super().__init__(master)
        logger.info("Opening add OTP entry window")
        self.title("Add OTP Entry")
        self.geometry(self.master.otp.config.get("otp_add_geometry", "500x300"))

        # Instructions
        tkinter.Label(self, text="Add a new OTP entry", font=("Arial", 12, "bold")).grid(
            row=0, column=0, columnspan=3, padx=5, pady=10
        )

        # Filename input
        self.label_filename = tkinter.Label(self, text="QR Code Image:")
        self.label_filename.grid(row=1, column=0, padx=5, pady=5, sticky=tkinter.E)
        self.entry_filename = tkinter.Entry(self, width=35)
        self.entry_filename.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.button_filemanager = tkinter.Button(self, text="Browse...",
                                                 command=self.click_button_filemanager)
        self.button_filemanager.grid(row=1, column=2, padx=5, pady=5)

        # Read QR button
        self.button_read = tkinter.Button(self, text="Read QR Code",
                                          command=self.on_click_read_qr)
        self.button_read.grid(row=2, column=1, pady=5)

        # Separator
        tkinter.Label(self, text="— OR —").grid(row=3, column=0, columnspan=3, pady=5)

        # Manual URI input
        self.label_text = tkinter.Label(self, text="OTP URL:")
        self.label_text.grid(row=4, column=0, padx=5, pady=5, sticky=tkinter.E)
        self.entry_text = tkinter.Entry(self, width=35)
        self.entry_text.grid(row=4, column=1, padx=5, pady=5, sticky="ew")

        # Add button
        self.button_add = tkinter.Button(self, text="Add OTP Entry",
                                         command=self.on_click_add,
                                         bg="green", fg="white")
        self.button_add.grid(row=5, column=1, pady=15)

        # Configure column weights for resizing
        self.grid_columnconfigure(1, weight=1)

        self.transient(master)
        self.grab_set()

    def click_button_filemanager(self):
        """Open file dialog to select QR code image."""
        logger.debug("Opening file manager to choose file")
        files = [
            ("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"),
            ("PNG files", "*.png"),
            ("All files", "*.*")
        ]
        file_path = filedialog.askopenfilename(filetypes=files)
        if file_path:
            self.entry_filename.delete(0, tkinter.END)
            self.entry_filename.insert(0, str(file_path))

    def on_click_read_qr(self):
        """Read OTP URI from QR code image."""
        logger.debug("Reading QR code from image")

        filename = self.entry_filename.get().strip()
        if not filename:
            messagebox.showwarning("No File", "Please select a QR code image first.")
            return

        try:
            text = service.read_uri_from_qr_image(filename)
            self.entry_text.delete(0, tkinter.END)
            self.entry_text.insert(0, str(text))
            messagebox.showinfo("Success", "QR code read successfully!")
        except FileNotFoundError as e:
            messagebox.showerror("File Error", str(e))
        except exceptions.QRCodeNotFoundError as e:
            messagebox.showerror("QR Code Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")

    def on_click_add(self):
        """Add OTP entry to vault."""
        logger.debug("Attempting to add OTP entry")
        uri_text = self.entry_text.get().strip()

        if not uri_text:
            messagebox.showwarning("Empty Input", "Please enter an OTP URL.")
            return

        try:
            self.master.otp.add_uri(uri_text, time.time())
            self.master.otp.save()
            self.master.update_rows()
            messagebox.showinfo("Success", "OTP entry added successfully!")
            self.destroy()
        except exceptions.UriError as err:
            messagebox.showerror("Invalid URI", f"Could not add URI: {err}")
        except Exception as err:
            messagebox.showerror("Error", f"Unexpected error: {err}")


class ChangePw(tkinter.Toplevel):
    """Dialog window for changing vault password."""

    def __init__(self, master):
        super().__init__(master)
        logger.info("Opening change password window")
        self.title("Change Password")
        self.geometry(self.master.otp.config.get("pw_change_geometry", "400x250"))

        # Title
        tkinter.Label(self, text="Set New Password", font=("Arial", 12, "bold")).grid(
            row=0, column=0, columnspan=2, padx=5, pady=15
        )

        # Password 1
        self.label_password_1 = tkinter.Label(self, text="New Password:")
        self.label_password_1.grid(row=1, column=0, padx=5, pady=10, sticky=tkinter.E)
        self.entry_password_1 = tkinter.Entry(self, width=25, show='*')
        self.entry_password_1.grid(row=1, column=1, padx=5, pady=10, sticky="w")
        self.entry_password_1.focus()

        # Password 2
        self.label_password_2 = tkinter.Label(self, text="Confirm Password:")
        self.label_password_2.grid(row=2, column=0, padx=5, pady=10, sticky=tkinter.E)
        self.entry_password_2 = tkinter.Entry(self, width=25, show='*')
        self.entry_password_2.grid(row=2, column=1, padx=5, pady=10, sticky="w")
        self.entry_password_2.bind('<Return>', lambda e: self.on_click_set())

        # Password strength hint
        tkinter.Label(self, text="Minimum 4 characters", fg="gray", font=("Arial", 8)).grid(
            row=3, column=1, sticky="w", padx=5
        )

        # Set button
        tkinter.Button(self, text="Change Password", command=self.on_click_set,
                       bg="blue", fg="white").grid(row=4, column=0, columnspan=2, pady=20)

        self.transient(master)
        self.grab_set()

    def on_click_set(self):
        """Set new password after validation."""
        logger.info("Attempting to set new password")

        password1 = self.entry_password_1.get()
        password2 = self.entry_password_2.get()

        if password1 != password2:
            messagebox.showwarning("Password Mismatch", "Passwords do not match!")
            return

        if len(password1) < 4:
            messagebox.showwarning("Password Too Short", "Password must be at least 4 characters long!")
            return

        if messagebox.askyesno("Confirm Password Change",
                               "Are you sure you want to change the password?"):
            try:
                self.master.otp.set_new_password(password1)
                self.master.otp.save()
                messagebox.showinfo("Success", "Password changed successfully!")
                self.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Could not change password: {e}")


class QRCodeWindow(tkinter.Toplevel):
    """Dialog window for displaying OTP QR code."""

    def __init__(self, master, uri: str, name: str = "OTP Entry"):
        super().__init__(master)
        logger.info(f"Opening QR code window for: {name}")
        self.title(f"QR Code - {name}")
        self.geometry("450x550")
        self.uri = uri
        self.name = name

        # Check if QR generator is available
        if not QR_AVAILABLE:
            tkinter.Label(self, text="QR Code generation not available",
                          font=("Arial", 12), fg="red").pack(pady=20)
            tkinter.Label(self, text="Please install: pip install qrcode[pil]").pack(pady=10)
            tkinter.Button(self, text="Close", command=self.destroy).pack(pady=20)
            self.transient(master)
            return

        # Title
        title_label = tkinter.Label(self, text=name, font=("Arial", 14, "bold"))
        title_label.pack(pady=10)

        # Subtitle
        subtitle_label = tkinter.Label(self, text="Scan this QR code with your authenticator app",
                                       fg="gray")
        subtitle_label.pack(pady=5)

        # QR Code container frame
        qr_frame = tkinter.Frame(self, bg="white", relief=tkinter.SUNKEN, borderwidth=2)
        qr_frame.pack(pady=15, padx=20)

        # Generate and display QR code
        self.qr_label = tkinter.Label(qr_frame, bg="white")
        self.qr_label.pack(padx=10, pady=10)

        # Generate QR code
        self._generate_qr_code()

        # Buttons frame
        button_frame = tkinter.Frame(self)
        button_frame.pack(pady=15)

        # Save button
        save_btn = tkinter.Button(button_frame, text="Save as PNG",
                                  command=self.on_save_qr,
                                  width=15)
        save_btn.pack(side=tkinter.LEFT, padx=5)

        # Copy URI button
        copy_btn = tkinter.Button(button_frame, text="Copy URI",
                                  command=self.on_copy_uri,
                                  width=15)
        copy_btn.pack(side=tkinter.LEFT, padx=5)

        # Close button
        close_btn = tkinter.Button(button_frame, text="Close",
                                   command=self.destroy,
                                   width=15)
        close_btn.pack(side=tkinter.LEFT, padx=5)

        # Info text
        info_text = ("Note: Anyone with this QR code can generate your OTP codes.\n"
                     "Keep this QR code secure!")
        info_label = tkinter.Label(self, text=info_text, fg="red",
                                   font=("Arial", 9), justify=tkinter.CENTER)
        info_label.pack(pady=10)

        self.transient(master)
        self.grab_set()

    def _generate_qr_code(self):
        """Generate and display QR code."""
        try:
            # Generate QR code (350x350 pixels)
            qr_photo = qr_generator.QRGenerator.generate_qr_photoimage(self.uri, size=350)

            if qr_photo:
                # Keep reference to prevent garbage collection
                self.qr_photo = qr_photo
                self.qr_label.config(image=qr_photo)
                logger.info("QR code displayed successfully")
            else:
                self.qr_label.config(text="Failed to generate QR code",
                                     font=("Arial", 12), fg="red")
                logger.error("QR code generation failed")

        except Exception as e:
            logger.error(f"Error displaying QR code: {e}")
            self.qr_label.config(text=f"Error: {e}", font=("Arial", 10), fg="red")

    def on_save_qr(self):
        """Save QR code to file."""
        logger.debug("Saving QR code to file")

        # Suggest filename based on entry name
        safe_name = "".join(c for c in self.name if c.isalnum() or c in (' ', '-', '_'))
        default_filename = f"QR_{safe_name}.png"

        filepath = filedialog.asksaveasfilename(
            defaultextension=".png",
            initialfile=default_filename,
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            title="Save QR Code"
        )

        if filepath:
            try:
                success = qr_generator.QRGenerator.save_qr_to_file(self.uri, filepath, size=500)
                if success:
                    messagebox.showinfo("Success", f"QR code saved to:\n{filepath}")
                else:
                    messagebox.showerror("Error", "Failed to save QR code")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save QR code: {e}")

    def on_copy_uri(self):
        """Copy OTP URI to clipboard."""
        logger.debug("Copying URI to clipboard")
        try:
            self.clipboard_clear()
            self.clipboard_append(self.uri)
            messagebox.showinfo("Copied", "OTP URI copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Could not copy URI: {e}")


if __name__ == '__main__':
    # Test windows
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("Extra Windows Module - Ready for import")
