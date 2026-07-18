# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Main GUI Module - OTP Manager Application.

Provides the main window with search, sort, clipboard copy, and lazy loading.
"""

import logging
import time
import tkinter
import tkinter.messagebox
from tkinter import filedialog, ttk

import exceptions
import extra_windows
import otp_class

logger = logging.getLogger(__name__)

# Constants
LAZY_LOAD_BATCH_SIZE = 50
CLIPBOARD_CLEAR_DELAY_MS = 30000  # 30 seconds


class PasswordWindow(tkinter.Toplevel):
    """Password input window for unlocking the vault."""

    def __init__(self, master, on_success):
        super().__init__(master)
        logger.info("Opening password input window")
        self.geometry(self.master.otp.config.get("pw_enter_geometry", "600x250"))
        self.title("Password Window")
        self.on_success = on_success

        tkinter.Label(self, text="Enter the Password for saved OTP").pack(pady=20)

        self.password_entry = tkinter.Entry(self, show="*", width=20)
        self.password_entry.pack()
        self.password_entry.bind('<Return>', lambda e: self.send_password())
        self.password_entry.focus()

        tkinter.Button(self, text="Unlock", command=self.send_password).pack(pady=20)

        self.transient(master)
        self.grab_set()

        # Suspend the main window's global mousewheel binding while this
        # modal dialog is open, and restore it once the dialog closes.
        master.unbind_mousewheel()
        self.bind("<Destroy>", lambda e: master.bind_mousewheel())

    def send_password(self):
        """Attempt to unlock vault with entered password."""
        logger.info("Password button clicked")
        try:
            self.master.otp.unlock_with_password(self.password_entry.get())
            self.on_success()
            self.destroy()
        except exceptions.InvalidPasswordError as e:
            tkinter.messagebox.showerror("Fehler", str(e))
        except Exception as e:
            tkinter.messagebox.showerror("Unerwarteter Fehler", f"Ein Fehler ist aufgetreten: {e}")


class App(tkinter.Tk):
    """Main application window with OTP management."""

    def __init__(self):
        super().__init__()
        self.title("Py OTP GUI")

        self.otp = otp_class.OtpClass()
        self.otp_numbers = {}
        self.displayed_uris = []  # For lazy loading
        self.current_filter = ""
        self.current_sort = otp_class.SortOrder.NAME_ASC
        self.clipboard_clear_timer = None
        self.otp_update_timer = None
        self.status_clear_timer = None

        self.geometry(self.otp.config.get("main_geometry", "1000x600"))

        self._create_widgets()

        # Protocol for closing window
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        if not self.otp.is_unlocked:
            logger.info("Requesting password")
            self.after_idle(lambda: PasswordWindow(self, on_success=self.on_vault_unlocked))
        else:
            self.on_vault_unlocked()

    def _create_widgets(self):
        """Create all GUI widgets."""

        # --- Top Frame: Search and Sort ---
        top_frame = tkinter.Frame(self)
        top_frame.pack(side="top", fill="x", padx=10, pady=10)

        # Search
        tkinter.Label(top_frame, text="Search:").pack(side="left", padx=5)
        self.search_entry = tkinter.Entry(top_frame, width=30)
        self.search_entry.pack(side="left", padx=5)
        self.search_entry.bind('<KeyRelease>', self.on_search_change)

        tkinter.Button(top_frame, text="Clear", command=self.clear_search).pack(side="left", padx=5)

        # Sort
        tkinter.Label(top_frame, text="Sort:").pack(side="left", padx=20)
        self.sort_var = tkinter.StringVar(value="Name ↑")
        sort_options = ["Name ↑", "Name ↓", "Date ↑", "Date ↓"]
        self.sort_combo = ttk.Combobox(top_frame, textvariable=self.sort_var,
                                       values=sort_options, state="readonly", width=10)
        self.sort_combo.pack(side="left", padx=5)
        self.sort_combo.bind('<<ComboboxSelected>>', self.on_sort_change)

        # Entry count
        self.count_label = tkinter.Label(top_frame, text="Entries: 0")
        self.count_label.pack(side="right", padx=10)

        # --- Middle Frame: OTP List with Scrollbar ---
        middle_frame = tkinter.Frame(self)
        middle_frame.pack(side="top", fill="both", expand=True, padx=10)

        # Scrollbar
        scrollbar = tkinter.Scrollbar(middle_frame)
        scrollbar.pack(side="right", fill="y")

        # Canvas for scrolling
        self.canvas = tkinter.Canvas(middle_frame, yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.canvas.yview)

        # Frame inside canvas for OTP entries
        self.otp_list_frame = tkinter.Frame(self.canvas)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.otp_list_frame, anchor="nw")

        # Configure canvas scrolling
        self.otp_list_frame.bind('<Configure>', self._on_frame_configure)
        self.canvas.bind('<Configure>', self._on_canvas_configure)

        # Mouse wheel scrolling (bound/unbound around modal dialogs, see
        # bind_mousewheel/unbind_mousewheel - bind_all reaches every widget
        # in the process, including Toplevel dialogs, so it must be switched
        # off while one is open or it scrolls the list underneath them)
        self.bind_mousewheel()

        # --- Bottom Frame: Control Buttons ---
        control_frame = tkinter.Frame(self)
        control_frame.pack(side="bottom", fill="x", pady=10)

        tkinter.Button(control_frame, text="Lock Vault",
                       command=self.on_click_lock).pack(side="left", padx=5)

        tkinter.Button(control_frame, text="Change Password",
                       command=self.on_click_pw_change).pack(side="left", padx=5)

        tkinter.Button(control_frame, text="Export JSON",
                       command=self.on_click_export).pack(side="left", padx=5)

        tkinter.Button(control_frame, text="Import JSON",
                       command=self.on_click_import).pack(side="left", padx=5)

        tkinter.Button(control_frame, text="Add OTP URL",
                       command=self.on_click_add).pack(side="right", padx=5)

        # Transient status message (e.g. "Copied!") instead of a blocking dialog
        self.status_var = tkinter.StringVar(value="")
        self.status_label = tkinter.Label(control_frame, textvariable=self.status_var, fg="green")
        self.status_label.pack(side="left", padx=15)

    def _on_frame_configure(self, event=None):
        """Update scrollregion when frame size changes."""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        """Update canvas window width when canvas is resized."""
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling (Windows/Mac <MouseWheel>, X11 Button-4/5)."""
        if event.num == 4:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self.canvas.yview_scroll(1, "units")
        else:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def bind_mousewheel(self):
        """(Re-)enable list scrolling. Call after a modal dialog closes."""
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

    def unbind_mousewheel(self):
        """Disable list scrolling. Call while a modal dialog is open."""
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _show_status(self, message: str, duration_ms: int = 3000):
        """Show a transient, non-blocking status message instead of a dialog."""
        self.status_var.set(message)
        if self.status_clear_timer:
            self.after_cancel(self.status_clear_timer)
        self.status_clear_timer = self.after(duration_ms, lambda: self.status_var.set(""))

    def on_vault_unlocked(self):
        """Called when vault is successfully unlocked."""
        logger.info("Vault unlocked, displaying entries")
        self.update_rows()

    def create_row(self, uri: str, row_index: int):
        """
        Create a single OTP entry row.

        Args:
            uri: OTP URI to display
            row_index: Row index in grid
        """
        logger.debug(f"Creating row {row_index}")
        entry = self.otp.get_entry(uri)
        if not entry:
            return

        parent_frame = self.otp_list_frame

        # OTP Code
        number_str = tkinter.StringVar(parent_frame, self.otp.gen_otp_number(uri))
        self.otp_numbers[uri] = number_str

        code_entry = tkinter.Entry(parent_frame, textvariable=number_str,
                                   state="readonly", width=10, font=("Courier", 12, "bold"))
        code_entry.grid(row=row_index, column=0, padx=5, pady=2)

        # Copy button
        copy_btn = tkinter.Button(parent_frame, text="📋",
                                  command=lambda: self.copy_to_clipboard(uri))
        copy_btn.grid(row=row_index, column=1, padx=2, pady=2)

        # QR Code button
        qr_btn = tkinter.Button(parent_frame, text="🔲",
                                command=lambda: self.show_qr_code(uri))
        qr_btn.grid(row=row_index, column=2, padx=2, pady=2)

        # Name/URI
        name_text = entry.name if entry.name != "Unknown" else uri[:60]
        name_label = tkinter.Label(parent_frame, text=name_text, anchor="w")
        name_label.grid(row=row_index, column=3, padx=5, pady=2, sticky="w")

        # Created date
        time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.created_at))
        date_label = tkinter.Label(parent_frame, text=f"Created: {time_str}", fg="gray")
        date_label.grid(row=row_index, column=4, padx=5, pady=2)

        # Delete button
        delete_btn = tkinter.Button(parent_frame, text="Delete",
                                    command=lambda: self.delete(uri))
        delete_btn.grid(row=row_index, column=5, padx=5, pady=2)

    def copy_to_clipboard(self, uri: str):
        """
        Copy OTP code to clipboard with auto-clear.

        Args:
            uri: URI of the OTP to copy
        """
        code = self.otp.gen_otp_number(uri)
        if code and code != "-1":
            self.clipboard_clear()
            self.clipboard_append(code)
            logger.info("Copied OTP to clipboard")

            # Show feedback without blocking further copies
            self._show_status("Copied! Clipboard clears in 30s")

            # Cancel previous timer if exists
            if self.clipboard_clear_timer:
                self.after_cancel(self.clipboard_clear_timer)

            # Set new timer to clear clipboard
            self.clipboard_clear_timer = self.after(CLIPBOARD_CLEAR_DELAY_MS,
                                                    self._auto_clear_clipboard)

    def _auto_clear_clipboard(self):
        """Clear clipboard automatically after timeout."""
        try:
            self.clipboard_clear()
            logger.info("Auto-cleared clipboard")
        except Exception as e:
            logger.warning(f"Could not auto-clear clipboard: {e}")

    def _update_all_otps(self):
        """Batch update all visible OTP codes."""
        if not self.otp.is_unlocked:
            return

        current_time = time.time()
        logger.debug(f"Batch updating {len(self.otp_numbers)} OTP codes")

        # Batch generate all codes at once
        uris = list(self.otp_numbers.keys())
        codes = self.otp.gen_otp_batch(uris, current_time)

        # Update display
        for uri, number_var in self.otp_numbers.items():
            if uri in codes:
                number_var.set(codes[uri])

        # Schedule next update
        self.otp_update_timer = self.after(5000, self._update_all_otps)

    def update_rows(self, lazy_load: bool = True):
        """
        Update OTP entry display.

        Args:
            lazy_load: Use lazy loading for large lists
        """
        if not self.otp.is_unlocked:
            return

        logger.info("Updating OTP entry display")

        # Clear existing entries
        for widget in self.otp_list_frame.winfo_children():
            widget.destroy()
        self.otp_numbers.clear()

        # Get filtered and sorted URIs
        uris = self.otp.search(self.current_filter) if self.current_filter else list(self.otp.get_uri())

        # Sort URIs
        all_sorted = []
        for uri in uris:
            entry = self.otp.get_entry(uri)
            if entry:
                all_sorted.append((uri, entry))

        if self.current_sort == otp_class.SortOrder.NAME_ASC:
            all_sorted.sort(key=lambda x: x[1].name.lower())
        elif self.current_sort == otp_class.SortOrder.NAME_DESC:
            all_sorted.sort(key=lambda x: x[1].name.lower(), reverse=True)
        elif self.current_sort == otp_class.SortOrder.DATE_ASC:
            all_sorted.sort(key=lambda x: x[1].created_at)
        elif self.current_sort == otp_class.SortOrder.DATE_DESC:
            all_sorted.sort(key=lambda x: x[1].created_at, reverse=True)

        sorted_uris = [uri for uri, _ in all_sorted]

        # Update count
        self.count_label.config(text=f"Entries: {len(sorted_uris)}")

        # Lazy loading for large lists
        if lazy_load and len(sorted_uris) > LAZY_LOAD_BATCH_SIZE:
            logger.info(f"Using lazy loading for {len(sorted_uris)} entries")
            self.displayed_uris = sorted_uris[:LAZY_LOAD_BATCH_SIZE]

            # Create initial batch
            for index, uri in enumerate(self.displayed_uris):
                self.create_row(uri, index)

            # Add "Load More" button
            remaining = len(sorted_uris) - LAZY_LOAD_BATCH_SIZE
            load_more_btn = tkinter.Button(self.otp_list_frame,
                                           text=f"Load More ({remaining} remaining)",
                                           command=lambda: self._load_more_entries(sorted_uris))
            load_more_btn.grid(row=len(self.displayed_uris), column=0, columnspan=6, pady=10)
        else:
            # Display all entries
            for index, uri in enumerate(sorted_uris):
                self.create_row(uri, index)

        # Restart OTP update timer (cancel any existing chain to avoid stacking timers)
        if self.otp_update_timer:
            self.after_cancel(self.otp_update_timer)
            self.otp_update_timer = None
        self._update_all_otps()

    def _load_more_entries(self, all_uris: list):
        """Load next batch of entries (lazy loading)."""
        current_count = len(self.displayed_uris)
        next_batch = all_uris[current_count:current_count + LAZY_LOAD_BATCH_SIZE]

        # Remove "Load More" button
        for widget in self.otp_list_frame.winfo_children():
            if isinstance(widget, tkinter.Button) and "Load More" in widget.cget("text"):
                widget.destroy()

        # Add next batch
        for uri in next_batch:
            index = len(self.displayed_uris)
            self.create_row(uri, index)
            self.displayed_uris.append(uri)

        # Add "Load More" button if more entries remain
        if len(self.displayed_uris) < len(all_uris):
            remaining = len(all_uris) - len(self.displayed_uris)
            load_more_btn = tkinter.Button(self.otp_list_frame,
                                           text=f"Load More ({remaining} remaining)",
                                           command=lambda: self._load_more_entries(all_uris))
            load_more_btn.grid(row=len(self.displayed_uris), column=0, columnspan=6, pady=10)

    def show_qr_code(self, uri: str):
        """
        Show QR code window for OTP entry.

        Args:
            uri: URI to display as QR code
        """
        logger.info("Opening QR code window")
        entry = self.otp.get_entry(uri)
        if entry:
            extra_windows.QRCodeWindow(self, uri, entry.name)

    def on_search_change(self, event=None):
        """Handle search input change."""
        self.current_filter = self.search_entry.get().strip()
        logger.debug(f"Search changed: '{self.current_filter}'")
        self.update_rows()

    def clear_search(self):
        """Clear search field and show all entries."""
        self.search_entry.delete(0, tkinter.END)
        self.current_filter = ""
        self.update_rows()

    def on_sort_change(self, event=None):
        """Handle sort option change."""
        sort_text = self.sort_var.get()

        sort_map = {
            "Name ↑": otp_class.SortOrder.NAME_ASC,
            "Name ↓": otp_class.SortOrder.NAME_DESC,
            "Date ↑": otp_class.SortOrder.DATE_ASC,
            "Date ↓": otp_class.SortOrder.DATE_DESC,
        }

        self.current_sort = sort_map.get(sort_text, otp_class.SortOrder.NAME_ASC)
        logger.debug(f"Sort changed: {self.current_sort}")
        self.update_rows()

    def delete(self, uri_to_delete: str):
        """
        Delete an OTP entry with confirmation.

        Args:
            uri_to_delete: URI to delete
        """
        logger.info("Attempting to delete entry")

        entry = self.otp.get_entry(uri_to_delete)
        name = entry.name if entry else uri_to_delete[:50]

        if tkinter.messagebox.askyesno("Löschen bestätigen",
                                       f"Möchtest du '{name}' wirklich löschen?"):
            self.otp.delete_uri(uri_to_delete)
            self.otp.save()
            self.update_rows()

    def on_click_add(self):
        """Open add OTP dialog."""
        logger.info("Opening add OTP dialog")
        if self.otp.is_unlocked:
            extra_windows.AddOtp(self)

    def on_click_pw_change(self):
        """Open password change dialog."""
        logger.info("Opening password change dialog")
        if self.otp.is_unlocked:
            extra_windows.ChangePw(self)

    def on_click_lock(self):
        """Lock the vault and prompt for the password again."""
        if not self.otp.is_unlocked:
            return

        logger.info("Locking vault via UI")

        # Stop background timers while locked
        if self.otp_update_timer:
            self.after_cancel(self.otp_update_timer)
            self.otp_update_timer = None
        if self.clipboard_clear_timer:
            self.after_cancel(self.clipboard_clear_timer)
            self.clipboard_clear_timer = None
        if self.status_clear_timer:
            self.after_cancel(self.status_clear_timer)
            self.status_clear_timer = None

        # Don't leave a copied code sitting in the clipboard past a lock
        self._auto_clear_clipboard()

        self.otp.lock()

        # Clear the displayed entries
        for widget in self.otp_list_frame.winfo_children():
            widget.destroy()
        self.otp_numbers.clear()
        self.count_label.config(text="Entries: 0")
        self.status_var.set("")

        PasswordWindow(self, on_success=self.on_vault_unlocked)

    def on_click_export(self):
        """Export OTP entries to JSON file."""
        if not self.otp.is_unlocked:
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export OTP Entries"
        )

        if filepath:
            try:
                self.otp.export_to_json(filepath)
                count = len(self.otp.decrypted_data)
                tkinter.messagebox.showinfo("Export Successful",
                                            f"Exported {count} entries to:\n{filepath}")
            except Exception as e:
                tkinter.messagebox.showerror("Export Failed", f"Could not export: {e}")

    def on_click_import(self):
        """Import OTP entries from JSON file."""
        if not self.otp.is_unlocked:
            return

        filepath = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import OTP Entries"
        )

        if filepath:
            try:
                imported, skipped = self.otp.import_from_json(filepath)
                self.otp.save()
                self.update_rows()

                tkinter.messagebox.showinfo("Import Complete",
                                            f"Imported: {imported}\nSkipped: {skipped}")
            except Exception as e:
                tkinter.messagebox.showerror("Import Failed", f"Could not import: {e}")

    def on_closing(self):
        """Handle window close event."""
        logger.info("Closing application and saving settings")

        # Cancel clipboard clear timer
        if self.clipboard_clear_timer:
            self.after_cancel(self.clipboard_clear_timer)

        # Cancel OTP update timer
        if self.otp_update_timer:
            self.after_cancel(self.otp_update_timer)

        # Cancel status message timer
        if self.status_clear_timer:
            self.after_cancel(self.status_clear_timer)

        # Save window geometry
        self.otp.config.set("main_geometry", self.geometry())

        # Save configuration
        self.otp.save()

        # Close window
        self.destroy()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger.info("Starting OTP Manager Application")

    app = App()
    app.mainloop()
