"""Shared pytest fixtures."""

import sys
from pathlib import Path

# Allow `import otp_class`, `import crypt_utils`, etc. from the project root
# since the modules use flat (non-package) imports.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import config_manager


@pytest.fixture(autouse=True)
def isolated_config_dir(tmp_path, monkeypatch):
    """Redirect ConfigManager to a throwaway directory for every test.

    Without this, OtpClass() would read/write the user's real
    ~/.config/ThaOTP/config.json.
    """
    monkeypatch.setattr(
        config_manager.ConfigManager,
        "_get_config_path",
        staticmethod(lambda app_name: tmp_path),
    )
    return tmp_path
