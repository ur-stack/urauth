"""Tests for password hashing."""

from __future__ import annotations

import pytest

from urauth.authn.password import PasswordHasher


class TestPasswordHasher:
    def test_hash_and_verify(self) -> None:
        hasher = PasswordHasher()
        hashed = hasher.hash("my-password")
        assert hashed != "my-password"
        assert hasher.verify("my-password", hashed)
        assert not hasher.verify("wrong-password", hashed)

    def test_different_hashes_for_same_password(self) -> None:
        hasher = PasswordHasher()
        h1 = hasher.hash("same")
        h2 = hasher.hash("same")
        assert h1 != h2  # Salt should differ
        assert hasher.verify("same", h1)
        assert hasher.verify("same", h2)

    def test_bcrypt_72_byte_limit_rejects_long_password(self) -> None:
        """bcrypt rejects passwords longer than 72 bytes — callers must truncate."""
        hasher = PasswordHasher()
        long_pw = "A" * 73
        with pytest.raises(ValueError, match="72 bytes"):
            hasher.hash(long_pw)

    def test_password_at_72_byte_boundary(self) -> None:
        """Exactly 72 bytes is the maximum accepted by bcrypt."""
        hasher = PasswordHasher()
        pw = "A" * 72
        hashed = hasher.hash(pw)
        assert hasher.verify(pw, hashed)

    def test_empty_password(self) -> None:
        hasher = PasswordHasher()
        hashed = hasher.hash("")
        assert hasher.verify("", hashed)
        assert not hasher.verify("not-empty", hashed)

    def test_unicode_password(self) -> None:
        hasher = PasswordHasher()
        pw = "p\u00e4ssw\u00f6rd-\U0001f512"  # pässwörd-🔒
        hashed = hasher.hash(pw)
        assert hasher.verify(pw, hashed)
        assert not hasher.verify("password", hashed)

    def test_verify_with_invalid_hash_raises(self) -> None:
        hasher = PasswordHasher()
        with pytest.raises((ValueError, Exception)):
            hasher.verify("password", "not-a-bcrypt-hash")
