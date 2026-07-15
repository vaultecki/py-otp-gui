"""Tests for otp_class.OtpClass."""

import json

import pytest

import exceptions
from otp_class import OtpClass, SortOrder

TOTP_URI_A = "otpauth://totp/Alpha:aaa@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Alpha"
TOTP_URI_B = "otpauth://totp/Beta:bbb@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Beta"


@pytest.fixture
def unlocked_otp():
    """A freshly-created, already-unlocked vault (no password set yet)."""
    otp = OtpClass()
    assert otp.is_unlocked
    return otp


def test_new_vault_starts_unlocked(unlocked_otp):
    assert unlocked_otp.is_unlocked
    assert unlocked_otp.decrypted_data == {}


def test_add_uri_creates_entry(unlocked_otp):
    unlocked_otp.add_uri(TOTP_URI_A, date=1000.0)

    entry = unlocked_otp.get_entry(TOTP_URI_A)
    assert entry is not None
    assert entry.uri == TOTP_URI_A
    assert entry.created_at == 1000.0
    assert entry.name == "aaa@example.com"


def test_add_duplicate_uri_raises(unlocked_otp):
    unlocked_otp.add_uri(TOTP_URI_A)
    with pytest.raises(exceptions.UriError):
        unlocked_otp.add_uri(TOTP_URI_A)


def test_add_invalid_uri_raises(unlocked_otp):
    with pytest.raises(exceptions.UriError):
        unlocked_otp.add_uri("not-an-otp-uri")


def test_add_empty_uri_raises(unlocked_otp):
    with pytest.raises(exceptions.UriError):
        unlocked_otp.add_uri("   ")


def test_gen_otp_number_returns_six_digits(unlocked_otp):
    unlocked_otp.add_uri(TOTP_URI_A)
    code = unlocked_otp.gen_otp_number(TOTP_URI_A)
    assert code != "-1"
    assert len(code) == 6
    assert code.isdigit()


def test_gen_otp_number_unknown_uri_returns_sentinel(unlocked_otp):
    assert unlocked_otp.gen_otp_number("otpauth://totp/Unknown?secret=X") == "-1"


def test_gen_otp_batch(unlocked_otp):
    unlocked_otp.add_uri(TOTP_URI_A)
    unlocked_otp.add_uri(TOTP_URI_B)

    results = unlocked_otp.gen_otp_batch([TOTP_URI_A, TOTP_URI_B], date=1_700_000_000.0)

    assert set(results.keys()) == {TOTP_URI_A, TOTP_URI_B}
    assert all(len(code) == 6 for code in results.values())


def test_search_matches_name_and_uri(unlocked_otp):
    unlocked_otp.add_uri(TOTP_URI_A)
    unlocked_otp.add_uri(TOTP_URI_B)

    assert unlocked_otp.search("alpha") == [TOTP_URI_A]
    assert unlocked_otp.search("BETA") == [TOTP_URI_B]
    assert unlocked_otp.search("nonexistent") == []
    assert set(unlocked_otp.search("")) == {TOTP_URI_A, TOTP_URI_B}


def test_delete_uri(unlocked_otp):
    unlocked_otp.add_uri(TOTP_URI_A)

    assert unlocked_otp.delete_uri(TOTP_URI_A) is True
    assert unlocked_otp.get_entry(TOTP_URI_A) is None
    assert unlocked_otp.delete_uri(TOTP_URI_A) is False


def test_get_sorted_uris_by_name(unlocked_otp):
    unlocked_otp.add_uri(TOTP_URI_B, date=1.0)
    unlocked_otp.add_uri(TOTP_URI_A, date=2.0)

    assert unlocked_otp.get_sorted_uris(SortOrder.NAME_ASC) == [TOTP_URI_A, TOTP_URI_B]
    assert unlocked_otp.get_sorted_uris(SortOrder.NAME_DESC) == [TOTP_URI_B, TOTP_URI_A]


def test_get_sorted_uris_by_date(unlocked_otp):
    unlocked_otp.add_uri(TOTP_URI_A, date=2.0)
    unlocked_otp.add_uri(TOTP_URI_B, date=1.0)

    assert unlocked_otp.get_sorted_uris(SortOrder.DATE_ASC) == [TOTP_URI_B, TOTP_URI_A]
    assert unlocked_otp.get_sorted_uris(SortOrder.DATE_DESC) == [TOTP_URI_A, TOTP_URI_B]


def test_set_new_password_rejects_short_password(unlocked_otp):
    with pytest.raises(ValueError):
        unlocked_otp.set_new_password("abc")


def test_save_and_reload_roundtrip_with_correct_password():
    otp = OtpClass()
    otp.set_new_password("correct horse")
    otp.add_uri(TOTP_URI_A, date=42.0)
    otp.save()

    reloaded = OtpClass()
    assert not reloaded.is_unlocked
    reloaded.unlock_with_password("correct horse")

    assert reloaded.is_unlocked
    entry = reloaded.get_entry(TOTP_URI_A)
    assert entry is not None
    assert entry.created_at == 42.0


def test_unlock_with_wrong_password_raises():
    otp = OtpClass()
    otp.set_new_password("correct horse")
    otp.add_uri(TOTP_URI_A)
    otp.save()

    reloaded = OtpClass()
    with pytest.raises(exceptions.InvalidPasswordError):
        reloaded.unlock_with_password("wrong password")
    assert not reloaded.is_unlocked


def test_unlock_with_empty_password_raises():
    otp = OtpClass()
    otp.set_new_password("correct horse")
    otp.save()

    reloaded = OtpClass()
    with pytest.raises(exceptions.InvalidPasswordError):
        reloaded.unlock_with_password("")


def test_lock_clears_key_and_data(unlocked_otp):
    unlocked_otp.set_new_password("correct horse")
    unlocked_otp.add_uri(TOTP_URI_A)

    unlocked_otp.lock()

    assert not unlocked_otp.is_unlocked
    assert unlocked_otp.decrypted_data == {}
    assert unlocked_otp.key is None


def test_export_to_json(unlocked_otp, tmp_path):
    unlocked_otp.add_uri(TOTP_URI_A, date=1.0)
    export_file = tmp_path / "export.json"

    unlocked_otp.export_to_json(str(export_file))

    data = json.loads(export_file.read_text())
    assert TOTP_URI_A in data
    assert data[TOTP_URI_A]["created_at"] == 1.0


def test_import_from_json_adds_new_entries(unlocked_otp, tmp_path):
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps({TOTP_URI_A: {"uri": TOTP_URI_A, "created_at": 5.0}}))

    imported, skipped = unlocked_otp.import_from_json(str(import_file))

    assert imported == 1
    assert skipped == 0
    assert unlocked_otp.get_entry(TOTP_URI_A).created_at == 5.0


def test_import_from_json_skips_duplicates(unlocked_otp, tmp_path):
    unlocked_otp.add_uri(TOTP_URI_A)
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps({TOTP_URI_A: {"uri": TOTP_URI_A, "created_at": 5.0}}))

    imported, skipped = unlocked_otp.import_from_json(str(import_file))

    assert imported == 0
    assert skipped == 1


def test_import_from_json_skips_invalid_entries(unlocked_otp, tmp_path):
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps({"not-a-valid-uri": {"uri": "not-a-valid-uri"}}))

    imported, skipped = unlocked_otp.import_from_json(str(import_file))

    assert imported == 0
    assert skipped == 1
