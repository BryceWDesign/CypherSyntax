from __future__ import annotations

import zipfile

import pytest

from check_green import (
    GreenCheckError,
    _record_digest,
    _safe_wheel_member,
    _validate_wheel,
)


def test_wheel_member_path_policy():
    assert _safe_wheel_member("cyphersyntax/session.py") is True
    assert _safe_wheel_member("") is False
    assert _safe_wheel_member("/absolute.py") is False
    assert _safe_wheel_member("\\absolute.py") is False
    assert _safe_wheel_member("../escape.py") is False
    assert _safe_wheel_member("cyphersyntax\\session.py") is False


def test_record_digest_uses_urlsafe_unpadded_sha256():
    assert (
        _record_digest(b"")
        == "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
    )


def test_wheel_validator_rejects_duplicate_members(tmp_path):
    wheel = tmp_path / "duplicate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("cyphersyntax/__init__.py", b"")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("cyphersyntax/__init__.py", b"")

    with pytest.raises(GreenCheckError, match="duplicate archive members"):
        _validate_wheel(wheel)


def test_wheel_validator_rejects_unsafe_members(tmp_path):
    wheel = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("../escape.py", b"")

    with pytest.raises(GreenCheckError, match="unsafe archive members"):
        _validate_wheel(wheel)
