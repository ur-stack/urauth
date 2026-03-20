"""Tests for transport implementations."""

from __future__ import annotations

from starlette.requests import Request

from urauth.fastapi.transport.bearer import BearerTransport
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
