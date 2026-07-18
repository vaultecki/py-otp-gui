"""Tests for service.read_uri_from_qr_image."""

import pytest
from PIL import Image

import exceptions
import service
from qr_generator import QRGenerator

TEST_URI = "otpauth://totp/TestApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestApp"


def test_read_uri_from_qr_image_decodes_valid_qr_code(tmp_path):
    qr_file = tmp_path / "qr.png"
    QRGenerator.save_qr_to_file(TEST_URI, str(qr_file))

    assert service.read_uri_from_qr_image(str(qr_file)) == TEST_URI


def test_read_uri_from_qr_image_missing_file_raises_file_not_found(tmp_path):
    missing_file = tmp_path / "missing.png"
    with pytest.raises(FileNotFoundError):
        service.read_uri_from_qr_image(str(missing_file))


def test_read_uri_from_qr_image_image_without_qr_code_raises(tmp_path):
    plain_image = tmp_path / "plain.png"
    Image.new("RGB", (100, 100), color="white").save(plain_image)

    with pytest.raises(exceptions.QRCodeNotFoundError):
        service.read_uri_from_qr_image(str(plain_image))


def test_read_uri_from_qr_image_unreadable_file_raises_file_not_found(tmp_path):
    garbage_file = tmp_path / "garbage.png"
    garbage_file.write_bytes(b"not a real image")

    with pytest.raises(FileNotFoundError):
        service.read_uri_from_qr_image(str(garbage_file))
