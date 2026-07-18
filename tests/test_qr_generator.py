"""Tests for qr_generator.QRGenerator."""

import tkinter

import pytest
from PIL import Image, ImageTk

import service
from qr_generator import QRGenerator

TEST_URI = "otpauth://totp/TestApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestApp"


def _tk_available() -> bool:
    """Whether a Tk root can actually be created (needs a display)."""
    try:
        root = tkinter.Tk()
        root.destroy()
        return True
    except tkinter.TclError:
        return False


TK_AVAILABLE = _tk_available()


def test_generate_qr_image_returns_pil_image():
    img = QRGenerator.generate_qr_image(TEST_URI)
    assert isinstance(img, Image.Image)


def test_generate_qr_image_uses_requested_size():
    img = QRGenerator.generate_qr_image(TEST_URI, size=150)
    assert img.size == (150, 150)


def test_generate_qr_image_default_size_is_300():
    img = QRGenerator.generate_qr_image(TEST_URI)
    assert img.size == (300, 300)


def test_generate_qr_image_handles_long_uri():
    long_uri = TEST_URI + "&note=" + "x" * 500
    img = QRGenerator.generate_qr_image(long_uri)
    assert isinstance(img, Image.Image)


@pytest.mark.skipif(not TK_AVAILABLE, reason="no display available for Tk")
def test_generate_qr_photoimage_returns_photoimage():
    root = tkinter.Tk()
    try:
        photo = QRGenerator.generate_qr_photoimage(TEST_URI)
        assert isinstance(photo, ImageTk.PhotoImage)
    finally:
        root.destroy()


def test_save_qr_to_file_writes_valid_png(tmp_path):
    target = tmp_path / "qr.png"
    result = QRGenerator.save_qr_to_file(TEST_URI, str(target))

    assert result is True
    assert target.is_file()
    with Image.open(target) as img:
        assert img.format == "PNG"


def test_save_qr_to_file_roundtrips_via_service(tmp_path):
    """Full round trip: generate a QR file, then read it back with service.py."""
    target = tmp_path / "qr.png"
    QRGenerator.save_qr_to_file(TEST_URI, str(target))

    decoded = service.read_uri_from_qr_image(str(target))
    assert decoded == TEST_URI


def test_save_qr_to_file_invalid_directory_returns_false(tmp_path):
    bad_path = tmp_path / "nonexistent_dir" / "qr.png"
    result = QRGenerator.save_qr_to_file(TEST_URI, str(bad_path))
    assert result is False
