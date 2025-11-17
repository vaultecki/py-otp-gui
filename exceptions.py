# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Custom Exception Classes for OTP Application.

This module defines application-specific exceptions for better
error handling and user feedback.
"""


class OTPException(Exception):
    """Base exception for all OTP application errors."""
    pass


class QRCodeNotFoundError(OTPException):
    """
    Raised when no QR code is found in an image.

    This can occur when:
    - Image doesn't contain a QR code
    - QR code is damaged or unreadable
    - Image format is not supported
    """

    def __init__(self, message: str = "Kein QR-Code im Bild gefunden"):
        self.message = message
        super().__init__(self.message)


class InvalidPasswordError(OTPException):
    """
    Raised when password validation or decryption fails.

    This can occur when:
    - Password is incorrect for decryption
    - Password doesn't meet minimum requirements
    - Vault is locked when unlocked vault is required
    """

    def __init__(self, message: str = "Ungültiges oder falsches Passwort"):
        self.message = message
        super().__init__(self.message)


class ConfigFileError(OTPException):
    """
    Raised when configuration file operations fail.

    This can occur when:
    - Config file is corrupted
    - File permissions prevent read/write
    - JSON parsing fails
    - Disk is full
    """

    def __init__(self, message: str = "Fehler bei der Konfigurationsdatei"):
        self.message = message
        super().__init__(self.message)


class UriError(OTPException):
    """
    Raised when OTP URI operations fail.

    This can occur when:
    - URI format is invalid
    - URI cannot be parsed by pyotp
    - Required URI parameters are missing
    - URI already exists in vault
    """

    def __init__(self, message: str = "Ungültige OTP URI"):
        self.message = message
        super().__init__(self.message)


class EncryptionError(OTPException):
    """
    Raised when encryption/decryption operations fail.

    This can occur when:
    - Key derivation fails
    - Encryption algorithm error
    - Data corruption during encryption
    """

    def __init__(self, message: str = "Verschlüsselungsfehler"):
        self.message = message
        super().__init__(self.message)


class VaultError(OTPException):
    """
    Raised for vault-related errors.

    This can occur when:
    - Vault initialization fails
    - Vault is in unexpected state
    - Salt generation/storage fails
    """

    def __init__(self, message: str = "Vault-Fehler"):
        self.message = message
        super().__init__(self.message)


# Error code constants for programmatic error handling
ERROR_CODES = {
    'QR_NOT_FOUND': 1001,
    'INVALID_PASSWORD': 1002,
    'CONFIG_FILE': 1003,
    'INVALID_URI': 1004,
    'ENCRYPTION': 1005,
    'VAULT': 1006,
}


def get_user_friendly_message(exception: Exception) -> str:
    """
    Convert exception to user-friendly German message.

    Args:
        exception: Exception instance

    Returns:
        User-friendly error message in German
    """
    error_messages = {
        QRCodeNotFoundError: "Der QR-Code konnte im Bild nicht gefunden werden. "
                             "Bitte stellen Sie sicher, dass das Bild einen gültigen QR-Code enthält.",

        InvalidPasswordError: "Das Passwort ist falsch oder ungültig. "
                              "Bitte versuchen Sie es erneut.",

        ConfigFileError: "Die Konfigurationsdatei konnte nicht gelesen oder ist beschädigt. "
                         "Möglicherweise müssen Sie die Anwendung neu installieren.",

        UriError: "Die OTP-URI ist ungültig oder konnte nicht verarbeitet werden. "
                  "Bitte überprüfen Sie das Format.",

        EncryptionError: "Ein Verschlüsselungsfehler ist aufgetreten. "
                         "Bitte kontaktieren Sie den Support.",

        VaultError: "Der Vault konnte nicht initialisiert oder verwendet werden. "
                    "Bitte versuchen Sie die Anwendung neu zu starten.",
    }

    exception_type = type(exception)

    if exception_type in error_messages:
        return error_messages[exception_type]

    # Fallback for unknown exceptions
    return f"Ein unerwarteter Fehler ist aufgetreten: {str(exception)}"


if __name__ == '__main__':
    # Test exceptions
    print("Testing custom exceptions:")
    print()

    exceptions_to_test = [
        QRCodeNotFoundError(),
        InvalidPasswordError("Passwort zu kurz"),
        ConfigFileError("Datei nicht gefunden"),
        UriError("otpauth:// fehlt"),
        EncryptionError(),
        VaultError(),
    ]

    for exc in exceptions_to_test:
        print(f"{exc.__class__.__name__}: {exc}")
        print(f"User message: {get_user_friendly_message(exc)}")
        print()
