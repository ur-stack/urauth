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

    def test_long_password_accepted(self) -> None:
        """scrypt has no length limit — long passwords hash and verify correctly."""
        hasher = PasswordHasher()
        long_pw = "A" * 1000
        hashed = hasher.hash(long_pw)
        assert hasher.verify(long_pw, hashed)
        assert not hasher.verify("A" * 999, hashed)

    def test_hash_format(self) -> None:
        """Hash must use the scrypt MCF prefix."""
        hasher = PasswordHasher()
        hashed = hasher.hash("pw")
        assert hashed.startswith("$scrypt$")

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

    def test_verify_with_invalid_hash_returns_false(self) -> None:
        """Malformed hash strings must return False, never raise."""
        hasher = PasswordHasher()
        assert not hasher.verify("password", "not-a-hash")
        assert not hasher.verify("password", "$scrypt$bad$format")
        assert not hasher.verify("password", "")
