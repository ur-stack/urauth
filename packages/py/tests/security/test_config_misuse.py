"""Security tests for AuthConfig misuse scenarios.

Validates that the configuration layer rejects insecure settings
and enforces minimum key strength requirements.
"""

from __future__ import annotations

import warnings

import pytest

from urauth.config import AuthConfig


class TestProductionModeRejectsInsecureConfig:
    """Production environment must reject all forms of weak/default keys."""

    def test_production_rejects_default_key(self) -> None:
        with pytest.raises((ValueError,), match="not allowed|not permitted"):
            AuthConfig(
                secret_key="CHANGE-ME-IN-PRODUCTION",
                environment="production",
            )

    def test_production_rejects_allow_insecure_key_true(self) -> None:
        with pytest.raises(ValueError, match="allow_insecure_key=True is not permitted in production"):
            AuthConfig(
                secret_key="a-perfectly-fine-secret-key-that-is-long-enough",
                environment="production",
                allow_insecure_key=True,
            )

    def test_production_accepts_strong_key(self) -> None:
        cfg = AuthConfig(
            secret_key="a-perfectly-fine-secret-key-that-is-long-enough",
            environment="production",
        )
        assert cfg.secret_key == "a-perfectly-fine-secret-key-that-is-long-enough"


class TestWeakSecretBlocklist:
    """Every entry in the weak secrets blocklist must be rejected."""

    @pytest.mark.parametrize(
        "weak_key",
        [
            "secret",
            "password",
            "changeme",
            "change-me",
            "test",
            "key",
            "mysecret",
            "jwt-secret",
        ],
    )
    def test_weak_secret_rejected(self, weak_key: str) -> None:
        with pytest.raises(ValueError, match="commonly used weak secret"):
            AuthConfig(
                secret_key=weak_key,
                environment="development",
            )

    @pytest.mark.parametrize(
        "weak_key",
        [
            "SECRET",
            "Password",
            "CHANGEME",
        ],
    )
    def test_weak_secret_case_insensitive(self, weak_key: str) -> None:
        """Blocklist comparison is case-insensitive."""
        with pytest.raises(ValueError, match="commonly used weak secret"):
            AuthConfig(
                secret_key=weak_key,
                environment="development",
            )


class TestHMACKeyLength:
    """HMAC algorithms require a minimum key length of 32 characters."""

    def test_short_hmac_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least 32 characters"):
            AuthConfig(
                secret_key="short-but-not-weak-key",
                environment="development",
                algorithm="HS256",
            )

    def test_short_key_rejected_hs384(self) -> None:
        with pytest.raises(ValueError, match="at least 32 characters"):
            AuthConfig(
                secret_key="short-but-not-weak-key",
                environment="development",
                algorithm="HS384",
            )

    def test_short_key_rejected_hs512(self) -> None:
        with pytest.raises(ValueError, match="at least 32 characters"):
            AuthConfig(
                secret_key="short-but-not-weak-key",
                environment="development",
                algorithm="HS512",
            )

    def test_exactly_32_chars_accepted(self) -> None:
        cfg = AuthConfig(
            secret_key="a" * 32,
            environment="development",
            algorithm="HS256",
        )
        assert len(cfg.secret_key) == 32


class TestWhitespaceAndEmptyKey:
    """Empty and whitespace-only keys must be rejected."""

    def test_whitespace_only_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty or whitespace-only"):
            AuthConfig(
                secret_key="   ",
                environment="development",
            )

    def test_tabs_only_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty or whitespace-only"):
            AuthConfig(
                secret_key="\t\t\t",
                environment="development",
            )

    def test_newlines_only_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty or whitespace-only"):
            AuthConfig(
                secret_key="\n\n\n",
                environment="development",
            )

    def test_empty_key_rejected(self) -> None:
        # Empty string stripped is empty, so it should fail
        with pytest.raises(ValueError, match="must not be empty or whitespace-only"):
            AuthConfig(
                secret_key="",
                environment="development",
            )


class TestTestingEnvironmentAutoAllowsInsecureKeys:
    """Testing environment should auto-set allow_insecure_key=True."""

    def test_testing_env_allows_default_key(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cfg = AuthConfig(
                secret_key="CHANGE-ME-IN-PRODUCTION",
                environment="testing",
            )
        assert cfg.allow_insecure_key is True

    def test_testing_env_allows_short_key(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cfg = AuthConfig(
                secret_key="short",
                environment="testing",
            )
        assert cfg.secret_key == "short"

    def test_testing_env_allows_weak_key(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cfg = AuthConfig(
                secret_key="secret",
                environment="testing",
            )
        assert cfg.secret_key == "secret"


class TestDevelopmentModeDefaultKeyWithoutInsecureFlag:
    """Development mode with default key but without allow_insecure_key should fail."""

    def test_dev_default_key_no_flag_fails(self) -> None:
        with pytest.raises(ValueError, match="Default secret key"):
            AuthConfig(
                secret_key="CHANGE-ME-IN-PRODUCTION",
                environment="development",
            )

    def test_dev_default_key_with_flag_warns(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            cfg = AuthConfig(
                secret_key="CHANGE-ME-IN-PRODUCTION",
                environment="development",
                allow_insecure_key=True,
            )
            assert cfg.secret_key == "CHANGE-ME-IN-PRODUCTION"
            assert any("default secret key" in str(warning.message).lower() for warning in w)
