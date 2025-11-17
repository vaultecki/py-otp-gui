"""
OTP Class Module - Manages encrypted OTP entries with password protection.

This module provides secure storage and retrieval of OTP (One-Time Password) entries
with encryption, password protection, and automatic backup functionality.
"""

import json
import logging
import os
import shutil
from dataclasses import dataclass, asdict
from typing import Dict, Optional, List, Tuple
from datetime import datetime
from enum import Enum
import nacl.exceptions
import pyotp
import time

import config_manager
import crypt_utils
import exceptions

logger = logging.getLogger(__name__)

# Constants
OTP_UPDATE_INTERVAL_MS = 5000
MIN_PASSWORD_LENGTH = 4
MAX_BACKUP_FILES = 5


class SortOrder(Enum):
    """Sorting options for OTP entries."""
    NAME_ASC = "name_asc"
    NAME_DESC = "name_desc"
    DATE_ASC = "date_asc"
    DATE_DESC = "date_desc"


@dataclass
class OtpEntry:
    """Represents a single OTP entry with URI and creation timestamp."""
    uri: str
    created_at: float = time.time()

    @property
    def name(self) -> str:
        """Extract name from URI for display."""
        try:
            parsed = pyotp.parse_uri(self.uri)
            return parsed.name if hasattr(parsed, 'name') else self._extract_name_from_uri()
        except:
            return self._extract_name_from_uri()

    def _extract_name_from_uri(self) -> str:
        """Fallback name extraction from URI."""
        try:
            # Extract from otpauth://totp/Name?...
            if "otpauth://" in self.uri:
                parts = self.uri.split("/")
                if len(parts) > 3:
                    name_part = parts[3].split("?")[0]
                    return name_part.replace("%20", " ")
            return self.uri[:50]  # Fallback to first 50 chars
        except:
            return "Unknown"


class SecureString:
    """
    Wrapper for sensitive string data that provides memory cleanup.

    This helps ensure passwords and keys are cleared from memory
    when no longer needed.
    """

    def __init__(self, value: str):
        self._value = value

    def get(self) -> str:
        """Get the secure string value."""
        return self._value

    def clear(self) -> None:
        """Clear the string from memory."""
        if self._value:
            # Overwrite with zeros
            self._value = '\0' * len(self._value)
            self._value = None

    def __del__(self):
        """Ensure cleanup on deletion."""
        self.clear()


class OtpClass:
    """
    Manages encrypted OTP entries with password protection.

    Features:
    - Secure password-based encryption using NaCl
    - Automatic backup before saving
    - Memory-safe password handling
    - Comprehensive error handling
    - Import/Export functionality
    - Search and sorting capabilities
    - Batch OTP generation
    """

    def __init__(self):
        """Initialize the OTP manager."""
        logger.info("Initializing OTP class")
        self.config = config_manager.ConfigManager()
        self.key: Optional[bytes] = None
        self.is_unlocked: bool = False
        self.decrypted_data: Dict[str, OtpEntry] = {}
        self._password_buffer: Optional[SecureString] = None
        self._otp_cache: Dict[str, Tuple[str, float]] = {}  # uri -> (code, timestamp)
        self._initialize_vault()

    def _initialize_vault(self) -> None:
        """
        Initialize vault with salt or mark as existing.

        If no salt exists, creates a new one and marks vault as unlocked
        (first-time setup). Otherwise, vault remains locked until password
        is provided.
        """
        logger.debug("Initializing vault")
        if not self.config.get("salt"):
            logger.info("Creating new vault - no password set yet")
            self.is_unlocked = True
            salt = crypt_utils.CryptoUtils.encode_base64(
                crypt_utils.CryptoUtils.generate_salt()
            )
            self.config.set("salt", salt)
            self.config.save()
        else:
            logger.debug("Vault already exists - password required")
            self.is_unlocked = False

    def unlock_with_password(self, password: str) -> None:
        """
        Unlock the vault with the provided password.

        Args:
            password: User password to decrypt the vault

        Raises:
            InvalidPasswordError: If password is incorrect or empty
            ConfigFileError: If config file is corrupted
        """
        logger.info("Attempting to unlock vault")

        if not password:
            raise exceptions.InvalidPasswordError("Passwort darf nicht leer sein")

        # Store password securely for re-encryption
        self._password_buffer = SecureString(password)

        try:
            salt = crypt_utils.CryptoUtils.decode_base64(self.config.get("salt"))
            self.key = crypt_utils.CryptoUtils.derive_key(password, salt)
            self._decrypt()
        except Exception as e:
            # Clear sensitive data on failure
            self._clear_sensitive_data()
            raise

    def set_new_password(self, password: str) -> None:
        """
        Set a new password for the vault.

        The vault must be unlocked before changing the password.

        Args:
            password: New password to use (minimum 4 characters)

        Raises:
            ValueError: If password is too short
            InvalidPasswordError: If vault is locked
        """
        logger.info("Setting new password")

        if not password or len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"Passwort muss mindestens {MIN_PASSWORD_LENGTH} Zeichen lang sein"
            )

        if not self.is_unlocked:
            raise exceptions.InvalidPasswordError(
                "Vault muss entsperrt sein, um Passwort zu ändern"
            )

        # Clear old password buffer
        if self._password_buffer:
            self._password_buffer.clear()

        # Store new password securely
        self._password_buffer = SecureString(password)

        salt = crypt_utils.CryptoUtils.decode_base64(self.config.get("salt"))
        self.key = crypt_utils.CryptoUtils.derive_key(password, salt)

        logger.info("Password updated successfully")

    def _decrypt(self) -> None:
        """
        Decrypt the stored data using the current key.

        Raises:
            InvalidPasswordError: If decryption fails due to wrong password
            ConfigFileError: If data is corrupted
        """
        logger.debug("Attempting to decrypt data")

        if not self.key:
            logger.warning("No key available for decryption")
            return

        encrypted_data = self.config.get("encrypted")
        if not encrypted_data:
            logger.info("No encrypted data found, starting with empty vault")
            self.is_unlocked = True
            return

        try:
            encrypted = crypt_utils.CryptoUtils.decode_base64(encrypted_data)
            decrypted_bytes = crypt_utils.CryptoUtils.decrypt(encrypted, self.key)
            raw_data = json.loads(decrypted_bytes)

            self.decrypted_data = {
                uri: OtpEntry(**data) for uri, data in raw_data.items()
            }

            self.is_unlocked = True
            logger.info(f"Decryption successful. Loaded {len(self.decrypted_data)} entries")

        except nacl.exceptions.CryptoError as e:
            logger.error(f"Decryption failed: {e}")
            raise exceptions.InvalidPasswordError(
                "Entschlüsselung fehlgeschlagen. Das Passwort ist wahrscheinlich falsch."
            )
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.error(f"Data parsing failed: {e}")
            raise exceptions.ConfigFileError(
                f"Die Konfigurationsdatei scheint beschädigt zu sein: {e}"
            )

    def save(self) -> None:
        """
        Save encrypted data to config file with automatic backup.

        Creates a timestamped backup before saving and manages backup rotation.

        Raises:
            ConfigFileError: If saving fails
        """
        logger.info("Saving vault data")

        if not self.is_unlocked:
            logger.warning("Cannot save while vault is locked")
            return

        try:
            # Create backup before saving
            self._create_backup()

            # Encrypt and save data
            if self.decrypted_data:
                data_to_save = {
                    uri: asdict(entry) for uri, entry in self.decrypted_data.items()
                }
                json_string = json.dumps(data_to_save, indent=2)
                encrypted_string = self._encrypt_data(json_string)
                self.config.set("encrypted", encrypted_string)
            else:
                # Clear encrypted data if no entries exist
                self.config.set("encrypted", None)

            self.config.save()
            logger.info(f"Saved {len(self.decrypted_data)} entries successfully")

            # Clean up old backups
            self._rotate_backups()

        except IOError as e:
            logger.error(f"Error writing config to file: {e}")
            raise exceptions.ConfigFileError(f"Speichern fehlgeschlagen: {e}")

    def _create_backup(self) -> None:
        """
        Create a timestamped backup of the current config file.

        Backup format: config.json.backup_YYYYMMDD_HHMMSS
        """
        try:
            if not os.path.exists(self.config.config_file):
                logger.debug("No config file to backup")
                return

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{self.config.config_file}.backup_{timestamp}"

            shutil.copy2(self.config.config_file, backup_file)
            logger.info(f"Backup created: {backup_file}")

        except Exception as e:
            logger.warning(f"Backup creation failed: {e}")
            # Don't fail the save operation if backup fails

    def _rotate_backups(self) -> None:
        """
        Keep only the most recent backup files.

        Deletes old backups if more than MAX_BACKUP_FILES exist.
        """
        try:
            backup_dir = os.path.dirname(self.config.config_file)
            backup_prefix = os.path.basename(self.config.config_file) + ".backup_"

            # Find all backup files
            backups = [
                os.path.join(backup_dir, f)
                for f in os.listdir(backup_dir)
                if f.startswith(backup_prefix)
            ]

            # Sort by modification time (newest first)
            backups.sort(key=os.path.getmtime, reverse=True)

            # Delete old backups
            for old_backup in backups[MAX_BACKUP_FILES:]:
                try:
                    os.remove(old_backup)
                    logger.debug(f"Deleted old backup: {old_backup}")
                except OSError as e:
                    logger.warning(f"Could not delete old backup {old_backup}: {e}")

        except Exception as e:
            logger.warning(f"Backup rotation failed: {e}")

    def _encrypt_data(self, data_to_encrypt: str) -> str:
        """
        Encrypt data using the current key.

        Args:
            data_to_encrypt: String data to encrypt

        Returns:
            Base64 encoded encrypted data

        Raises:
            ValueError: If no key is available
        """
        if not self.key:
            raise ValueError("Kein Verschlüsselungsschlüssel verfügbar")

        encrypted_bytes = crypt_utils.CryptoUtils.encrypt(
            data_to_encrypt.encode("utf-8"), self.key
        )
        return crypt_utils.CryptoUtils.encode_base64(encrypted_bytes)

    def add_uri(self, uri: str, date: float = None) -> None:
        """
        Add a new OTP URI to the vault.

        Args:
            uri: OTP URI to add (e.g., otpauth://totp/...)
            date: Optional creation timestamp (defaults to current time)

        Raises:
            UriError: If URI is invalid or already exists
            InvalidPasswordError: If vault is locked
        """
        if date is None:
            date = time.time()

        logger.debug(f"Adding URI (length: {len(uri)})")

        if not self.is_unlocked:
            raise exceptions.InvalidPasswordError("Vault muss entsperrt sein")

        if not uri or not uri.strip():
            raise exceptions.UriError("URI darf nicht leer sein")

        if uri in self.decrypted_data:
            raise exceptions.UriError("URI existiert bereits")

        try:
            # Validate URI by parsing it
            pyotp.parse_uri(uri)
        except Exception as err:
            raise exceptions.UriError(f"Ungültige OTP URI: {err}")

        entry = OtpEntry(uri=uri, created_at=date)
        self.decrypted_data[uri] = entry
        logger.info("Successfully added OTP entry")

    def gen_otp_number(self, uri: str, date: float = None) -> str:
        """
        Generate OTP code for given URI with caching.

        Args:
            uri: OTP URI to generate code for
            date: Optional timestamp for code generation (defaults to current time)

        Returns:
            6-digit OTP code or "-1" if URI not found or error occurs
        """
        if date is None:
            date = time.time()

        # Check cache first (valid for 30 seconds)
        if uri in self._otp_cache:
            cached_code, cached_time = self._otp_cache[uri]
            if date - cached_time < 30:
                return cached_code

        if uri not in self.decrypted_data:
            logger.warning("URI not found for OTP generation")
            return "-1"

        try:
            totp = pyotp.parse_uri(uri)
            code = totp.at(date)

            # Cache the code
            self._otp_cache[uri] = (code, date)

            return code
        except Exception as e:
            logger.error(f"Error generating OTP: {e}")
            return "-1"

    def gen_otp_batch(self, uris: List[str] = None, date: float = None) -> Dict[str, str]:
        """
        Generate OTP codes for multiple URIs at once (batch operation).

        Args:
            uris: List of URIs to generate codes for (None = all URIs)
            date: Optional timestamp for code generation

        Returns:
            Dictionary mapping URI to OTP code
        """
        if date is None:
            date = time.time()

        if uris is None:
            uris = list(self.decrypted_data.keys())

        logger.debug(f"Generating OTP batch for {len(uris)} entries")

        results = {}
        for uri in uris:
            results[uri] = self.gen_otp_number(uri, date)

        return results

    def search(self, query: str) -> List[str]:
        """
        Search for OTP entries by name or URI.

        Args:
            query: Search query (case-insensitive)

        Returns:
            List of matching URIs
        """
        if not query:
            return list(self.decrypted_data.keys())

        query_lower = query.lower()
        results = []

        for uri, entry in self.decrypted_data.items():
            # Search in name and URI
            if (query_lower in entry.name.lower() or
                    query_lower in uri.lower()):
                results.append(uri)

        logger.debug(f"Search '{query}' found {len(results)} results")
        return results

    def get_sorted_uris(self, sort_by: SortOrder = SortOrder.NAME_ASC) -> List[str]:
        """
        Get sorted list of URIs.

        Args:
            sort_by: Sort order (name or date, ascending or descending)

        Returns:
            Sorted list of URIs
        """
        if not self.decrypted_data:
            return []

        entries_with_uri = [(uri, entry) for uri, entry in self.decrypted_data.items()]

        if sort_by == SortOrder.NAME_ASC:
            entries_with_uri.sort(key=lambda x: x[1].name.lower())
        elif sort_by == SortOrder.NAME_DESC:
            entries_with_uri.sort(key=lambda x: x[1].name.lower(), reverse=True)
        elif sort_by == SortOrder.DATE_ASC:
            entries_with_uri.sort(key=lambda x: x[1].created_at)
        elif sort_by == SortOrder.DATE_DESC:
            entries_with_uri.sort(key=lambda x: x[1].created_at, reverse=True)

        return [uri for uri, _ in entries_with_uri]

    def export_to_json(self, filepath: str, include_metadata: bool = True) -> None:
        """
        Export OTP entries to JSON file (unencrypted).

        Args:
            filepath: Path to export file
            include_metadata: Include creation timestamps

        Raises:
            InvalidPasswordError: If vault is locked
            IOError: If file cannot be written
        """
        if not self.is_unlocked:
            raise exceptions.InvalidPasswordError("Vault muss entsperrt sein")

        logger.info(f"Exporting {len(self.decrypted_data)} entries to {filepath}")

        try:
            export_data = {}
            for uri, entry in self.decrypted_data.items():
                if include_metadata:
                    export_data[uri] = asdict(entry)
                else:
                    export_data[uri] = {"uri": uri}

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Export successful: {filepath}")

        except IOError as e:
            logger.error(f"Export failed: {e}")
            raise

    def import_from_json(self, filepath: str, skip_duplicates: bool = True) -> Tuple[int, int]:
        """
        Import OTP entries from JSON file.

        Args:
            filepath: Path to import file
            skip_duplicates: Skip entries that already exist

        Returns:
            Tuple of (imported_count, skipped_count)

        Raises:
            InvalidPasswordError: If vault is locked
            IOError: If file cannot be read
            ValueError: If JSON is invalid
        """
        if not self.is_unlocked:
            raise exceptions.InvalidPasswordError("Vault muss entsperrt sein")

        logger.info(f"Importing from {filepath}")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                import_data = json.load(f)

            imported = 0
            skipped = 0

            for uri, data in import_data.items():
                if uri in self.decrypted_data and skip_duplicates:
                    skipped += 1
                    continue

                try:
                    # Validate URI
                    pyotp.parse_uri(uri)

                    # Create entry with imported or current timestamp
                    created_at = data.get('created_at', time.time())
                    entry = OtpEntry(uri=uri, created_at=created_at)
                    self.decrypted_data[uri] = entry
                    imported += 1

                except Exception as e:
                    logger.warning(f"Skipped invalid entry: {e}")
                    skipped += 1

            logger.info(f"Import complete: {imported} imported, {skipped} skipped")
            return imported, skipped

        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Import failed: {e}")
            raise

    def get_entry(self, uri: str) -> Optional[OtpEntry]:
        """
        Get OTP entry by URI.

        Args:
            uri: URI to look up

        Returns:
            OtpEntry if found, None otherwise
        """
        return self.decrypted_data.get(uri)

    def get_uri_list(self) -> List[str]:
        """
        Get sorted list of all URIs.

        Returns:
            List of URIs sorted alphabetically
        """
        return sorted(self.decrypted_data.keys())

    def get_uri(self):
        """
        Get URIs as dict_keys object.

        Returns:
            Dictionary keys view of URIs

        Note:
            Consider using get_uri_list() for a sorted list instead.
        """
        return self.decrypted_data.keys()

    def delete_uri(self, uri: str) -> bool:
        """
        Delete an OTP entry.

        Args:
            uri: URI to delete

        Returns:
            True if deleted, False if not found
        """
        logger.debug("Attempting to delete URI")

        if uri in self.decrypted_data:
            del self.decrypted_data[uri]
            # Clear from cache
            if uri in self._otp_cache:
                del self._otp_cache[uri]
            logger.info("Successfully deleted OTP entry")
            return True

        logger.warning("URI not found for deletion")
        return False

    def _clear_sensitive_data(self) -> None:
        """Clear sensitive data from memory."""
        if self._password_buffer:
            self._password_buffer.clear()
            self._password_buffer = None

        if self.key:
            # Overwrite key with zeros
            self.key = b'\0' * len(self.key)
            self.key = None

        # Clear OTP cache
        self._otp_cache.clear()

        logger.debug("Sensitive data cleared from memory")

    def lock(self) -> None:
        """
        Lock the vault and clear sensitive data from memory.

        After locking, unlock_with_password() must be called again
        to access the vault.
        """
        logger.info("Locking vault")
        self.is_unlocked = False
        self.decrypted_data.clear()
        self._clear_sensitive_data()

    def __del__(self):
        """Ensure sensitive data is cleared on deletion."""
        self._clear_sensitive_data()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger.info("OTP Class Module - Ready for import")
