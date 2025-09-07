class QRCodeNotFoundError(Exception):
    """Wird ausgelöst, wenn kein QR-Code im Bild gefunden wird."""
    pass

class InvalidPasswordError(Exception):
    """Wird ausgelöst, wenn das Passwort zur Entschlüsselung falsch ist."""
    pass

class ConfigFileError(Exception):
    """Wird bei Problemen mit der Konfigurationsdatei ausgelöst."""
    pass
