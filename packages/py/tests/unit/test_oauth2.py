"""Tests for OAuth2 client — provider registration, PKCE, state generation."""

from __future__ import annotations

import base64
import hashlib
from unittest.mock import AsyncMock, patch

import pytest

from urauth.authn.oauth2.client import OAuthManager


@pytest.fixture
def manager() -> OAuthManager:
    mgr = OAuthManager()
    mgr.register("github", client_id="cid", client_secret="csec")
    return mgr


class TestProviderRegistration:
    def test_register_and_get_provider(self, manager: OAuthManager) -> None:
        config = manager._get_provider("github")  # pyright: ignore[reportPrivateUsage]
        assert config["client_id"] == "cid"
        assert config["client_secret"] == "csec"
        # Should also have github defaults (authorize_url, etc.)
        assert "authorize_url" in config

    def test_unregistered_provider_raises(self, manager: OAuthManager) -> None:
        with pytest.raises(ValueError, match="not registered"):
            manager._get_provider("unknown")  # pyright: ignore[reportPrivateUsage]

    def test_duplicate_register_is_noop(self) -> None:
        mgr = OAuthManager()
        mgr.register("github", client_id="first", client_secret="s1")
        mgr.register("github", client_id="second", client_secret="s2")
        config = mgr._get_provider("github")  # pyright: ignore[reportPrivateUsage]
        assert config["client_id"] == "first"


class TestAuthorizeParams:
    def test_returns_state_and_verifier(self, manager: OAuthManager) -> None:
        state, code_verifier, client_id = manager.build_authorize_params("github", "http://localhost/cb")
        assert len(state) > 20
        assert len(code_verifier) > 20
        assert client_id == "cid"

    def test_state_uniqueness(self, manager: OAuthManager) -> None:
        s1, _, _ = manager.build_authorize_params("github", "http://localhost/cb")
        s2, _, _ = manager.build_authorize_params("github", "http://localhost/cb")
        assert s1 != s2


class TestPKCE:
    async def test_pkce_s256_correctness(self, manager: OAuthManager) -> None:
        """Verify code_challenge = base64url(sha256(code_verifier))."""
        _, code_verifier, _ = manager.build_authorize_params("github", "http://localhost/cb")

        with patch.object(manager, "_get_endpoint", new_callable=AsyncMock) as mock_ep:
            mock_ep.return_value = "https://github.com/login/oauth/authorize"
            url = await manager.authorize_redirect_url("github", "http://localhost/cb", "state", code_verifier)

        # Parse code_challenge from URL
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        code_challenge = params["code_challenge"][0]
        assert params["code_challenge_method"] == ["S256"]

        # Verify S256: base64url(sha256(verifier)) without padding
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert code_challenge == expected


class TestAuthorizeURL:
    async def test_missing_endpoint_raises(self) -> None:
        mgr = OAuthManager()
        mgr.register("custom", client_id="c", client_secret="s")
        with pytest.raises(ValueError, match="No authorize_url"):
            await mgr.authorize_redirect_url("custom", "http://localhost/cb", "state", "verifier")
