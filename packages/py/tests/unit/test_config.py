"""Tests for AuthConfig — secure defaults and env override."""

from __future__ import annotations

from urauth.config import AuthConfig


class TestAuthConfigDefaults:
    def test_cookie_secure_by_default(self) -> None:
        cfg = AuthConfig(secret_key="test-key")
        assert cfg.cookie_secure is True

    def test_cookie_httponly_by_default(self) -> None:
        cfg = AuthConfig(secret_key="test-key")
        assert cfg.cookie_httponly is True

    def test_cookie_samesite_lax_by_default(self) -> None:
        cfg = AuthConfig(secret_key="test-key")
        assert cfg.cookie_samesite == "lax"

    def test_session_cookie_secure_by_default(self) -> None:
        cfg = AuthConfig(secret_key="test-key")
        assert cfg.session_cookie_secure is True
        assert cfg.session_cookie_httponly is True
        assert cfg.session_cookie_samesite == "lax"

    def test_default_algorithm_is_hs256(self) -> None:
        cfg = AuthConfig(secret_key="test-key")
        assert cfg.algorithm == "HS256"

    def test_default_ttls(self) -> None:
        cfg = AuthConfig(secret_key="test-key")
        assert cfg.access_token_ttl == 900  # 15 min
        assert cfg.refresh_token_ttl == 604800  # 7 days

    def test_csrf_disabled_by_default(self) -> None:
        cfg = AuthConfig(secret_key="test-key")
        assert cfg.csrf_enabled is False

    def test_tenant_disabled_by_default(self) -> None:
        cfg = AuthConfig(secret_key="test-key")
        assert cfg.tenant_enabled is False


class TestAuthConfigOverrides:
    def test_env_prefix(self, monkeypatch: object) -> None:
        import os

        os.environ["AUTH_SECRET_KEY"] = "env-secret"
        os.environ["AUTH_ACCESS_TOKEN_TTL"] = "60"
        try:
            cfg = AuthConfig()  # type: ignore[call-arg]
            assert cfg.secret_key == "env-secret"
            assert cfg.access_token_ttl == 60
        finally:
            os.environ.pop("AUTH_SECRET_KEY", None)
            os.environ.pop("AUTH_ACCESS_TOKEN_TTL", None)

    def test_custom_values(self) -> None:
        cfg = AuthConfig(
            secret_key="my-key",
            algorithm="HS384",
            access_token_ttl=60,
            cookie_secure=False,
            cookie_samesite="strict",
            token_issuer="my-app",
            token_audience="my-api",
        )
        assert cfg.algorithm == "HS384"
        assert cfg.access_token_ttl == 60
        assert cfg.cookie_secure is False
        assert cfg.cookie_samesite == "strict"
        assert cfg.token_issuer == "my-app"
        assert cfg.token_audience == "my-api"
