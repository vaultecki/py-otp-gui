# VaultOTP

A desktop OTP (TOTP) manager with a Tkinter GUI. Entries are stored encrypted
in a local JSON config file.

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## Features

- Password-protected vault (minimum 4 characters)
- Add entries by scanning a QR code image or pasting an `otpauth://` URI
- Generate TOTP codes, refreshed automatically every 30 seconds
- Search and sort entries by name or creation date
- Lazy-loaded entry list (loads 50 at a time)
- Copy code to clipboard, with automatic clear after 30 seconds
- Export/import entries as JSON
- Show a QR code for an existing entry (e.g. to re-scan on another device)
- Timestamped backups on save, keeping the 5 most recent

## Requirements

- Python 3.8+
- Windows, Linux, or macOS

On very recent Python releases, `opencv-python` (and its `numpy` dependency)
may not yet have prebuilt wheels, which can make `pip install` try to compile
numpy from source and fail. If that happens, use a Python version with
existing wheels (e.g. 3.11-3.13) until upstream catches up.

## Installation

```bash
git clone <repo-url>
cd py-otp-gui
pip install .
python main.py
```

Dependencies: `pillow`, `PyNaCl`, `opencv-python`, `pyotp`, `qrcode`.

## Usage

### First run

No password is set initially, so the vault starts unlocked. Add an entry,
then use "Change Password" to encrypt the vault.

### Adding entries

- **QR code**: "Add OTP URL" → "Browse..." to pick an image → "Read QR Code"
  → "Add OTP Entry"
- **Manual**: "Add OTP URL" → paste an `otpauth://totp/...` URI → "Add OTP
  Entry"

### Export / Import

Export writes an **unencrypted** JSON file containing all entries. Import
reads such a file and skips duplicates.

## File structure

```
main.py             GUI application window
otp_class.py         vault logic (storage, encryption, OTP generation)
extra_windows.py     secondary dialog windows
config_manager.py    config file read/write, backups
crypt_utils.py        encryption helpers
qr_generator.py      QR code generation
service.py           QR code reading
exceptions.py        custom exception types
tests/                pytest test suite
```

## Data storage

Config file location:

- Windows: `%LOCALAPPDATA%\ThaOTP\config.json`
- Linux/macOS: `~/.config/ThaOTP/config.json`

Backups are written next to the config file as
`config.json.backup_<timestamp>`; only the 5 most recent are kept.

OTP secrets are encrypted in `config.json`. JSON exports are not encrypted.

## Known limitations

Memory safety is partial. The derived encryption key and the password buffer
are held in mutable `bytearray`s and are zeroed when the vault is locked.
Decrypted OTP secrets (the `otpauth://` URIs, including the Base32 secret)
are plain Python strings, which are immutable, so the application cannot
forcibly scrub them from memory. Locking the vault only drops the
application's references to them; a memory dump taken shortly afterward
could still contain leftover secret data until the garbage collector
reclaims it.

## Development

All dependencies, ruff settings, and mypy settings live in `pyproject.toml`.
Install dev dependencies:

```bash
pip install ".[dev]"
```

Run tests:

```bash
pytest
```

Lint:

```bash
ruff check .
```

Type-check:

```bash
mypy .
```

Pre-commit hooks run automatically once installed: ruff, mypy, and basic file
hygiene on `git commit`; the (slower) test suite on `git push`.

```bash
pre-commit install --hook-type pre-commit --hook-type pre-push
```

CI runs the same lint, type-check, and test steps on every push and pull
request (`.github/workflows/ci.yml`).

## License

Apache License, Version 2.0. See `LICENSE`.

## Disclaimer

Provided "as is", without warranty of any kind. Keep independent backups of
your OTP secrets.
