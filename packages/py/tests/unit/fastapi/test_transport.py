"""Tests for transport implementations."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import Response

from urauth.config import AuthConfig
from urauth.fastapi.transport.bearer import BearerTransport
from urauth.fastapi.transport.cookie import CookieTransport
from urauth.fastapi.transport.header import HeaderTransport
from urauth.fastapi.transport.hybrid import HybridTransport


def _make_request(headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    return Request(scope)


class TestBearerTransport:
    def test_extract(self) -> None:
        t = BearerTransport()
        req = _make_request({"Authorization": "Bearer abc123"})
        assert t.extract_token(req) == "abc123"

    def test_extract_missing(self) -> None:
        t = BearerTransport()
        req = _make_request({})
        assert t.extract_token(req) is None

    def test_extract_wrong_scheme(self) -> None:
        t = BearerTransport()
        req = _make_request({"Authorization": "Basic abc123"})
        assert t.extract_token(req) is None


class TestHeaderTransport:
    def test_extract(self) -> None:
        t = HeaderTransport("X-API-Key")
        req = _make_request({"X-API-Key": "my-key"})
        assert t.extract_token(req) == "my-key"

    def test_extract_missing(self) -> None:
        t = HeaderTransport("X-API-Key")
        req = _make_request({})
        assert t.extract_token(req) is None


class TestHybridTransport:
    def test_bearer_first(self) -> None:
        bearer = BearerTransport()
        header = HeaderTransport("X-API-Key")
        hybrid = HybridTransport(bearer, header)

        req = _make_request({"Authorization": "Bearer tok1", "X-API-Key": "tok2"})
        assert hybrid.extract_token(req) == "tok1"

    def test_fallback(self) -> None:
        bearer = BearerTransport()
        header = HeaderTransport("X-API-Key")
        hybrid = HybridTransport(bearer, header)

        req = _make_request({"X-API-Key": "tok2"})
        assert hybrid.extract_token(req) == "tok2"

    def test_none(self) -> None:
        hybrid = HybridTransport(BearerTransport())
        req = _make_request({})
        assert hybrid.extract_token(req) is None


def _make_cookie_request(cookies: dict[str, str]) -> Request:
    """Create a request with cookies."""
    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"cookie", cookie_header.encode())] if cookies else [],
    }
    return Request(scope)


class TestCookieTransport:
    def test_extract_from_cookie(self) -> None:
        config = AuthConfig(secret_key="test", cookie_name="access_token")
        t = CookieTransport(config)
        req = _make_cookie_request({"access_token": "my-token"})
        assert t.extract_token(req) == "my-token"

    def test_extract_missing_cookie(self) -> None:
        config = AuthConfig(secret_key="test", cookie_name="access_token")
        t = CookieTransport(config)
        req = _make_cookie_request({})
        assert t.extract_token(req) is None

    def test_set_token(self) -> None:
        config = AuthConfig(secret_key="test", cookie_name="access_token", cookie_secure=True, cookie_httponly=True)
        t = CookieTransport(config)
        response = Response()
        t.set_token(response, "new-token")
        # Check that the set-cookie header is present
        cookie_headers = [h for h in response.headers.getlist("set-cookie") if "access_token" in h]
        assert len(cookie_headers) == 1
        assert "new-token" in cookie_headers[0]
        assert "httponly" in cookie_headers[0].lower()
        assert "secure" in cookie_headers[0].lower()

    def test_delete_token(self) -> None:
        config = AuthConfig(secret_key="test", cookie_name="access_token")
        t = CookieTransport(config)
        response = Response()
        t.delete_token(response)
        cookie_headers = [h for h in response.headers.getlist("set-cookie") if "access_token" in h]
        assert len(cookie_headers) == 1
        # Deleted cookie should have max-age=0 or expires in the past
        assert 'max-age=0' in cookie_headers[0].lower() or '="";' in cookie_headers[0]

    def test_custom_cookie_name(self) -> None:
        config = AuthConfig(secret_key="test", cookie_name="my_auth")
        t = CookieTransport(config)
        req = _make_cookie_request({"my_auth": "tok123"})
        assert t.extract_token(req) == "tok123"


class TestCookieTransportSecurityAttributes:
    def test_samesite_attribute(self) -> None:
        config = AuthConfig(secret_key="test", cookie_samesite="strict")
        t = CookieTransport(config)
        response = Response()
        t.set_token(response, "tok")
        cookie = next(h for h in response.headers.getlist("set-cookie") if "access_token" in h)
        assert "samesite=strict" in cookie.lower()

    def test_domain_and_path_in_set_cookie(self) -> None:
        config = AuthConfig(secret_key="test", cookie_domain=".example.com", cookie_path="/api")
        t = CookieTransport(config)
        response = Response()
        t.set_token(response, "tok")
        cookie = next(h for h in response.headers.getlist("set-cookie") if "access_token" in h)
        assert ".example.com" in cookie
        assert "path=/api" in cookie.lower()

    def test_delete_cookie_uses_domain_and_path(self) -> None:
        config = AuthConfig(secret_key="test", cookie_domain=".example.com", cookie_path="/api")
        t = CookieTransport(config)
        response = Response()
        t.delete_token(response)
        cookie = next(h for h in response.headers.getlist("set-cookie") if "access_token" in h)
        assert ".example.com" in cookie
        assert "path=/api" in cookie.lower()


class TestHybridTransportWithCookie:
    def test_bearer_priority_over_cookie(self) -> None:
        config = AuthConfig(secret_key="test")
        bearer = BearerTransport()
        cookie = CookieTransport(config)
        hybrid = HybridTransport(bearer, cookie)

        # Request with both bearer header and cookie
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (b"authorization", b"Bearer bearer-token"),
                (b"cookie", b"access_token=cookie-token"),
            ],
        }
        req = Request(scope)
        assert hybrid.extract_token(req) == "bearer-token"

    def test_cookie_fallback(self) -> None:
        config = AuthConfig(secret_key="test")
        bearer = BearerTransport()
        cookie = CookieTransport(config)
        hybrid = HybridTransport(bearer, cookie)

        req = _make_cookie_request({"access_token": "cookie-token"})
        assert hybrid.extract_token(req) == "cookie-token"

    def test_set_token_on_primary(self) -> None:
        config = AuthConfig(secret_key="test")
        bearer = BearerTransport()
        cookie = CookieTransport(config)
        hybrid = HybridTransport(bearer, cookie)

        response = Response()
        hybrid.set_token(response, "new-token")
        # HybridTransport delegates set_token to primary transport

    def test_delete_token_on_primary(self) -> None:
        config = AuthConfig(secret_key="test")
        bearer = BearerTransport()
        cookie = CookieTransport(config)
        hybrid = HybridTransport(bearer, cookie)

        response = Response()
        hybrid.delete_token(response)
