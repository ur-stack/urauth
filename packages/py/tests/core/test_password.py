"""Tests for password hashing."""

from __future__ import annotations

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
