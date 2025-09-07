import cv2

import exceptions

def read_uri_from_qr_image(filepath: str) -> str:
    """Liest ein QR-Code-Bild und gibt den enthaltenen Text zurück."""
    image = cv2.imread(filepath)
    if image is None:
        # Sei spezifischer über den Fehler
        raise FileNotFoundError(f"Bild unter dem Pfad '{filepath}' konnte nicht gefunden oder gelesen werden.")

    detector = cv2.QRCodeDetector()
    decoded_text, _, _ = detector.detectAndDecode(image)

    if not decoded_text:
        raise exceptions.QRCodeNotFoundError("Im Bild wurde kein QR-Code gefunden.")

    return decoded_text
