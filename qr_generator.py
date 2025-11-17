# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
QR Code Generator Module - Creates QR codes from OTP URIs.

This module generates QR codes that can be scanned by authenticator apps.
"""

import io
import logging
from typing import Optional
from PIL import Image, ImageTk
import qrcode

logger = logging.getLogger(__name__)


class QRGenerator:
    """
    Generate QR codes for OTP URIs.

    Uses the qrcode library to create QR codes that can be displayed
    in the GUI or saved to files.
    """

    @staticmethod
    def generate_qr_image(uri: str, size: int = 300) -> Optional[Image.Image]:
        """
        Generate QR code image from OTP URI.

        Args:
            uri: OTP URI (e.g., otpauth://totp/...)
            size: Size of the QR code in pixels

        Returns:
            PIL Image object or None on error
        """
        try:
            logger.debug(f"Generating QR code (size: {size})")

            # Create QR code
            qr = qrcode.QRCode(
                version=1,  # Auto-adjust size
                error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction
                box_size=10,
                border=4,
            )

            qr.add_data(uri)
            qr.make(fit=True)

            # Create image
            img = qr.make_image(fill_color="black", back_color="white")

            # Resize to desired size
            img = img.resize((size, size), Image.Resampling.LANCZOS)

            logger.debug("QR code generated successfully")
            return img

        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
            return None

    @staticmethod
    def generate_qr_photoimage(uri: str, size: int = 300) -> Optional[ImageTk.PhotoImage]:
        """
        Generate QR code as Tkinter PhotoImage.

        Args:
            uri: OTP URI
            size: Size in pixels

        Returns:
            PhotoImage for use in Tkinter or None on error
        """
        try:
            img = QRGenerator.generate_qr_image(uri, size)
            if img:
                photo = ImageTk.PhotoImage(img)
                return photo
            return None
        except Exception as e:
            logger.error(f"Failed to create PhotoImage: {e}")
            return None

    @staticmethod
    def save_qr_to_file(uri: str, filepath: str, size: int = 500) -> bool:
        """
        Save QR code to image file.

        Args:
            uri: OTP URI
            filepath: Path to save image (PNG recommended)
            size: Size in pixels

        Returns:
            True if successful, False otherwise
        """
        try:
            img = QRGenerator.generate_qr_image(uri, size)
            if img:
                img.save(filepath, "PNG")
                logger.info(f"QR code saved to: {filepath}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to save QR code: {e}")
            return False


if __name__ == '__main__':
    # Test QR code generation
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("Testing QR Generator")

    test_uri = "otpauth://totp/TestApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestApp"

    # Test image generation
    img = QRGenerator.generate_qr_image(test_uri)
    if img:
        logger.info("✓ QR image generated")
    else:
        logger.error("✗ QR image generation failed")

    # Test file saving
    if QRGenerator.save_qr_to_file(test_uri, "test_qr.png"):
        logger.info("✓ QR code saved to file")
    else:
        logger.error("✗ QR code save failed")
