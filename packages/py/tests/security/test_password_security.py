"""Security tests for password hashing.

Validates that the PasswordHasher produces proper salted hashes,
handles edge cases, and never stores plaintext.
"""

from __future__ import annotations

import pytest

from urauth.identity.password import PasswordHasher


@pytest.fixture
def hasher() -> PasswordHasher:
    # n=2**4 (16) is the minimum valid power-of-2; keeps tests fast
    return PasswordHasher(n=2**4)


class TestHashIsNotPlaintext:
    """Hash output must never equal the plaintext input."""

    def test_hash_differs_from_input(self, hasher: PasswordHasher) -> None:
        password = "my-secure-password-123"
        hashed = hasher.hash(password)
        assert hashed != password

    def test_hash_has_scrypt_prefix(self, hasher: PasswordHasher) -> None:
        hashed = hasher.hash("test-password")
        assert hashed.startswith("$scrypt$")


class TestHashSaltUniqueness:
    """Each call to hash() must produce a different result due to salt."""

    def test_same_password_different_hashes(self, hasher: PasswordHasher) -> None:
        password = "identical-password"
        hash1 = hasher.hash(password)
        hash2 = hasher.hash(password)
        assert hash1 != hash2

    def test_different_hashes_both_verify(self, hasher: PasswordHasher) -> None:
        password = "identical-password"
        hash1 = hasher.hash(password)
        hash2 = hasher.hash(password)
        assert hasher.verify(password, hash1) is True
        assert hasher.verify(password, hash2) is True


class TestCorrectPasswordVerifies:
    """Correct password must always verify."""

    def test_verify_correct(self, hasher: PasswordHasher) -> None:
        password = "correct-horse-battery-staple"
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True


class TestWrongPasswordFails:
    """Wrong password must never verify."""

    def test_verify_wrong(self, hasher: PasswordHasher) -> None:
        hashed = hasher.hash("correct-password")
        assert hasher.verify("wrong-password", hashed) is False

    def test_verify_similar_password(self, hasher: PasswordHasher) -> None:
        hashed = hasher.hash("password123")
        assert hasher.verify("password124", hashed) is False

    def test_verify_empty_vs_nonempty(self, hasher: PasswordHasher) -> None:
        hashed = hasher.hash("nonempty")
        assert hasher.verify("", hashed) is False


class TestEmptyPassword:
    """Empty password should be hashable and verifiable."""

    def test_empty_password_hash_and_verify(self, hasher: PasswordHasher) -> None:
        hashed = hasher.hash("")
        assert hashed != ""
        assert hasher.verify("", hashed) is True
        assert hasher.verify("notempty", hashed) is False


class TestVeryLongPassword:
    """scrypt has no length limit — long passwords must hash and verify correctly."""

    def test_1000_char_password(self, hasher: PasswordHasher) -> None:
        long_password = "a" * 1000
        hashed = hasher.hash(long_password)
        assert hasher.verify(long_password, hashed) is True

    def test_10000_char_password(self, hasher: PasswordHasher) -> None:
        very_long = "x" * 10_000
        hashed = hasher.hash(very_long)
        assert hasher.verify(very_long, hashed) is True

    def test_72_byte_password(self, hasher: PasswordHasher) -> None:
        password = "a" * 72
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True

    def test_73_byte_password(self, hasher: PasswordHasher) -> None:
        """scrypt has no 72-byte limit — passwords of any length work."""
        password = "a" * 73
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True


class TestUnicodePassword:
    """Unicode passwords must work correctly."""

    def test_emoji_password(self, hasher: PasswordHasher) -> None:
        password = "\U0001f512\U0001f511\U0001f4aa"
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True

    def test_cjk_password(self, hasher: PasswordHasher) -> None:
        password = "\u5bc6\u7801\u5b89\u5168"
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True

    def test_mixed_unicode_ascii(self, hasher: PasswordHasher) -> None:
        password = "hello-\u4e16\u754c-\U0001f30d"
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True


class TestNullBytesInPassword:
    """Null bytes in password should work or fail cleanly."""

    def test_password_with_null_byte(self, hasher: PasswordHasher) -> None:
        """scrypt (via hashlib) encodes as UTF-8 bytes — null bytes are handled."""
        password = "before\x00after"
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True
