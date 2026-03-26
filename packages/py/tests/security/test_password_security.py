"""Security tests for password hashing.

Validates that the PasswordHasher produces proper salted hashes,
handles edge cases, and never stores plaintext.
"""

from __future__ import annotations

import pytest

from urauth.authn.password import PasswordHasher


@pytest.fixture
def hasher() -> PasswordHasher:
    # Use low rounds for test speed
    return PasswordHasher(rounds=4)


class TestHashIsNotPlaintext:
    """Hash output must never equal the plaintext input."""

    def test_hash_differs_from_input(self, hasher: PasswordHasher) -> None:
        password = "my-secure-password-123"
        hashed = hasher.hash(password)
        assert hashed != password

    def test_hash_has_bcrypt_prefix(self, hasher: PasswordHasher) -> None:
        hashed = hasher.hash("test-password")
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")


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
    """Very long passwords must not crash.

    Note: modern bcrypt implementations raise ValueError for passwords >72 bytes
    rather than silently truncating. This is the safer behavior.
    """

    def test_1000_char_password_raises_or_succeeds(self, hasher: PasswordHasher) -> None:
        long_password = "a" * 1000
        try:
            hashed = hasher.hash(long_password)
            assert hasher.verify(long_password, hashed) is True
        except ValueError:
            pass  # bcrypt rejecting >72 byte passwords is valid

    def test_10000_char_password_raises_or_succeeds(self, hasher: PasswordHasher) -> None:
        very_long = "x" * 10_000
        try:
            hashed = hasher.hash(very_long)
            assert hasher.verify(very_long, hashed) is True
        except ValueError:
            pass  # bcrypt rejecting >72 byte passwords is valid

    def test_exactly_72_bytes_works(self, hasher: PasswordHasher) -> None:
        """Exactly 72 ASCII bytes should always work with bcrypt."""
        password = "a" * 72
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True

    def test_73_bytes_raises_valueerror(self, hasher: PasswordHasher) -> None:
        """73 bytes exceeds bcrypt limit -- should raise ValueError."""
        password = "a" * 73
        with pytest.raises(ValueError, match="72 bytes"):
            hasher.hash(password)


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
        """bcrypt implementations may reject null bytes. Either behavior is acceptable."""
        password = "before\x00after"
        try:
            hashed = hasher.hash(password)
            assert hasher.verify(password, hashed) is True
        except ValueError:
            pass  # bcrypt rejecting null bytes is a valid security behavior
