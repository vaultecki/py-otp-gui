"""Tests for config_manager.ConfigManager."""

import json
import os

import pytest

import config_manager
from config_manager import ConfigManager


@pytest.fixture
def config():
    """A fresh ConfigManager pointed at the isolated tmp_path (see conftest)."""
    return ConfigManager("TestApp", "config.json")


def test_init_creates_config_directory(config):
    assert config.config_path.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions only")
def test_init_sets_directory_permissions_owner_only(config):
    mode = config.config_path.stat().st_mode & 0o777
    assert mode == 0o700


def test_new_config_starts_empty(config):
    assert config.data == {}
    assert config.get_all() == {}


def test_set_and_get_roundtrip(config):
    config.set("key", "value")
    assert config.get("key") == "value"


def test_get_returns_default_for_missing_key(config):
    assert config.get("missing") is None
    assert config.get("missing", "fallback") == "fallback"


def test_delete_existing_key(config):
    config.set("key", "value")
    assert config.delete("key") is True
    assert config.has_key("key") is False


def test_delete_missing_key_returns_false(config):
    assert config.delete("missing") is False


def test_has_key(config):
    assert config.has_key("key") is False
    config.set("key", "value")
    assert config.has_key("key") is True


def test_clear(config):
    config.set("a", 1)
    config.set("b", 2)
    config.clear()
    assert config.get_all() == {}


def test_get_all_returns_copy_not_live_reference(config):
    config.set("key", "value")
    snapshot = config.get_all()
    snapshot["key"] = "mutated"
    assert config.get("key") == "value"


def test_repr_contains_app_name_and_entry_count(config):
    config.set("key", "value")
    text = repr(config)
    assert "TestApp" in text
    assert "1" in text


def test_save_writes_json_file(config):
    config.set("key", "value")
    config.save()

    assert config.config_file.is_file()
    on_disk = json.loads(config.config_file.read_text(encoding="utf-8"))
    assert on_disk == {"key": "value"}


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions only")
def test_save_sets_file_permissions_owner_only(config):
    config.set("key", "value")
    config.save()

    mode = config.config_file.stat().st_mode & 0o777
    assert mode == 0o600


def test_save_and_reload_roundtrip(config):
    config.set("key", "value")
    config.set("number", 42)
    config.save()

    reloaded = ConfigManager("TestApp", "config.json")
    assert reloaded.get("key") == "value"
    assert reloaded.get("number") == 42


def test_load_with_missing_file_leaves_empty_data(config):
    config.config_file.unlink(missing_ok=True)
    config.load()
    assert config.data == {}


def test_load_with_corrupted_json_falls_back_to_empty(config):
    config.config_file.write_text("not valid json {{{", encoding="utf-8")
    config.load()
    assert config.data == {}


def test_load_does_not_raise_on_os_error(config, monkeypatch):
    config.config_file.write_text("{}", encoding="utf-8")

    def raise_os_error(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(config_manager.json, "load", raise_os_error)
    config.load()
    assert config.data == {}
