"""Tests for the framework-agnostic RateLimiter."""
# pyright: reportUnknownMemberType=false

from __future__ import annotations

from typing import Any

import pytest

from urauth.ratelimit import KeyStrategy, RateLimiter


class TestKeyStrategy:
    def test_values(self) -> None:
        assert KeyStrategy.IP == "ip"
        assert KeyStrategy.IDENTITY == "identity"
        assert KeyStrategy.SESSION == "session"
        assert KeyStrategy.JWT == "jwt"


class TestRateLimiterKeyResolution:
    def test_ip_key(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(10, Duration.MINUTE)], key=KeyStrategy.IP)
        key = limiter.resolve_key(ip="1.2.3.4")
        assert "ip:1.2.3.4" in key

    def test_identity_key(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(10, Duration.MINUTE)], key=KeyStrategy.IDENTITY)
        key = limiter.resolve_key(user_id="user-42")
        assert "user:user-42" in key

    def test_session_key(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(10, Duration.MINUTE)], key=KeyStrategy.SESSION)
        key = limiter.resolve_key(session_id="sess-abc")
        assert "sess:sess-abc" in key

    def test_jwt_key(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(10, Duration.MINUTE)], key=KeyStrategy.JWT)
        key = limiter.resolve_key(jwt_sub="user-42")
        assert "jwt:user-42" in key

    def test_custom_key_func(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        def custom_key(**kw: Any) -> str:
            return f"custom:{kw.get('ip')}:{kw.get('user_id')}"

        limiter = RateLimiter(
            rates=[Rate(10, Duration.MINUTE)],
            key_func=custom_key,
        )
        key = limiter.resolve_key(ip="1.2.3.4", user_id="bob")
        assert key == "custom:1.2.3.4:bob"

    def test_prefix(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(10, Duration.MINUTE)], prefix="myapp")
        key = limiter.resolve_key(ip="1.2.3.4")
        assert key.startswith("myapp:")

    def test_identity_falls_back_to_ip(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(10, Duration.MINUTE)], key=KeyStrategy.IDENTITY)
        key = limiter.resolve_key(ip="1.2.3.4", user_id=None)
        assert "1.2.3.4" in key


class TestRateLimiterCheck:
    async def test_allows_within_limit(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(5, Duration.MINUTE)])
        for _ in range(5):
            assert await limiter.check("test-key") is True

    async def test_denies_over_limit(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(3, Duration.MINUTE)])
        for _ in range(3):
            await limiter.check("test-key-2")
        assert await limiter.check("test-key-2") is False

    async def test_different_keys_independent(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(2, Duration.MINUTE)])
        assert await limiter.check("key-a") is True
        assert await limiter.check("key-a") is True
        assert await limiter.check("key-a") is False
        # Different key still has budget
        assert await limiter.check("key-b") is True

    async def test_check_request(self) -> None:
        pytest.importorskip("pyrate_limiter")
        from pyrate_limiter import Duration, Rate  # type: ignore[reportMissingImports]

        limiter = RateLimiter(rates=[Rate(5, Duration.MINUTE)], key=KeyStrategy.IP)
        assert await limiter.check_request(ip="1.2.3.4") is True
