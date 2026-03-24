"""Strategy-specific context resolvers for FastAPI.

Each resolver implements the same interface::

    async def resolve(request: Request, *, optional: bool = False) -> AuthContext

The ``build_resolver`` factory creates the right resolver from a
:class:`~urauth.pipeline.Strategy` config object.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from starlette.requests import Request

from urauth.auth import Auth, maybe_await
from urauth.context import AuthContext
from urauth.exceptions import UnauthorizedError
from urauth.fastapi.transport.bearer import BearerTransport
from urauth.pipeline import (
    APIKeyStrategy,
    BasicAuthStrategy,
    JWTStrategy,
    SessionStrategy,
    Strategy,
)


class JWTResolver:
    """Resolve identity from JWT tokens via the configured transport.

    Delegates to :meth:`Auth.build_context` which handles validation,
    revocation checks, and user loading.
    """

    def __init__(self, auth: Auth, transport: Any) -> None:
        self._auth = auth
        self._transport = transport

    async def resolve(self, request: Request, *, optional: bool = False) -> AuthContext:
        raw_token = self._transport.extract_token(request)
        return await self._auth.build_context(raw_token, optional=optional, request=request)


class SessionResolver:
    """Resolve identity from a server-side session cookie.

    Reads the session ID from the cookie, looks up session data in the
    :class:`~urauth.backends.base.SessionStore`, and builds an
    :class:`~urauth.context.AuthContext` from the stored user.
    """

    def __init__(self, auth: Auth, cookie_name: str = "session_id") -> None:
        self._auth = auth
        self._cookie_name = cookie_name

    async def resolve(self, request: Request, *, optional: bool = False) -> AuthContext:
        session_id = request.cookies.get(self._cookie_name)
        if session_id is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError()

        if self._auth.session_store is None:
            raise RuntimeError("SessionStrategy requires a session_store on Auth")

        session_data = await self._auth.session_store.get(session_id)
        if session_data is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError("Session expired or invalid")

        user_id = session_data.get("user_id")
        if user_id is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError("Invalid session data")

        user = await maybe_await(self._auth.get_user(user_id))
        if user is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError("User not found")

        if not getattr(user, "is_active", True):
            raise UnauthorizedError("Inactive user")

        return await self._auth.build_user_context(user, request=request)


class BasicAuthResolver:
    """Resolve identity from HTTP Basic ``Authorization`` header.

    Re-authenticates on every request — no tokens or sessions.
    """

    def __init__(self, auth: Auth, realm: str = "Restricted") -> None:
        self._auth = auth
        self._realm = realm

    async def resolve(self, request: Request, *, optional: bool = False) -> AuthContext:
        auth_header = request.headers.get("authorization")
        if auth_header is None or not auth_header.lower().startswith("basic "):
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError()

        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
            raise UnauthorizedError("Malformed Basic credentials") from exc

        user = await maybe_await(self._auth.get_user_by_username(username))
        if user is None:
            raise UnauthorizedError("Invalid credentials")

        valid = await maybe_await(self._auth.verify_password(user, password))
        if not valid:
            raise UnauthorizedError("Invalid credentials")

        if not getattr(user, "is_active", True):
            raise UnauthorizedError("Inactive user")

        return await self._auth.build_user_context(user, request=request)


class APIKeyResolver:
    """Resolve identity from an API key in a header or query parameter.

    Delegates to :meth:`Auth.get_user_by_api_key` for key validation.
    """

    def __init__(
        self,
        auth: Auth,
        *,
        header_name: str = "X-API-Key",
        query_param: str | None = None,
    ) -> None:
        self._auth = auth
        self._header_name = header_name
        self._query_param = query_param

    async def resolve(self, request: Request, *, optional: bool = False) -> AuthContext:
        key = request.headers.get(self._header_name)
        if key is None and self._query_param:
            key = request.query_params.get(self._query_param)
        if key is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError()

        user = await maybe_await(self._auth.get_user_by_api_key(key))
        if user is None:
            raise UnauthorizedError("Invalid API key")

        if not getattr(user, "is_active", True):
            raise UnauthorizedError("Inactive user")

        return await self._auth.build_user_context(user, request=request)


class FallbackResolver:
    """Try multiple resolvers in order, return first success.

    Useful for APIs that accept both JWT and API key auth.
    """

    def __init__(self, resolvers: list[Any]) -> None:
        self._resolvers = resolvers

    async def resolve(self, request: Request, *, optional: bool = False) -> AuthContext:
        last_error: UnauthorizedError | None = None
        for resolver in self._resolvers:
            try:
                return await resolver.resolve(request, optional=False)
            except UnauthorizedError as exc:
                last_error = exc
                continue

        if optional:
            return AuthContext.anonymous(request=request)
        raise last_error or UnauthorizedError()


def build_resolver(strategy: Strategy, auth: Auth, transport: Any = None) -> Any:
    """Factory: build the right resolver from a strategy config."""
    if isinstance(strategy, JWTStrategy):
        if transport is None:
            transport = BearerTransport()
        return JWTResolver(auth, transport)

    if isinstance(strategy, SessionStrategy):
        return SessionResolver(auth, cookie_name=strategy.cookie_name)

    if isinstance(strategy, BasicAuthStrategy):
        return BasicAuthResolver(auth, realm=strategy.realm)

    if isinstance(strategy, APIKeyStrategy):
        return APIKeyResolver(auth, header_name=strategy.header_name, query_param=strategy.query_param)

    resolvers = [build_resolver(s, auth, transport) for s in strategy.strategies]
    return FallbackResolver(resolvers)
