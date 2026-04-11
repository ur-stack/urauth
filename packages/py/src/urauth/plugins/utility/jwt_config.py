"""JWT configuration plugin.

Convenience plugin for configuring JWT parameters without subclassing Auth.
Particularly useful when combined with other plugins in a plugins=[...] list.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from urauth.auth import Auth


class JWTPlugin:
    """Configure JWT token settings via the plugin interface.

    This plugin provides a declarative way to tune JWT behaviour within a
    ``plugins=[...]`` list rather than passing parameters directly to ``Auth``.

    Usage::

        from urauth.plugins.utility import JWTPlugin

        auth = Auth(
            plugins=[
                JWTPlugin(
                    access_ttl=300,      # 5 min access token
                    refresh_ttl=2592000, # 30 day refresh token
                    issuer="https://auth.myapp.com",
                    audience="myapp-api",
                    algorithm="RS256",
                )
            ],
            method=JWT(store=...),
            secret_key="...",
        )

    .. note::
        ``setup()`` overrides the values already set on ``auth.method``. Put
        this plugin *first* in the list if other plugins depend on the final JWT
        settings.
    """

    id = "jwt"

    def __init__(
        self,
        *,
        access_ttl: int | None = None,
        refresh_ttl: int | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        algorithm: str | None = None,
    ) -> None:
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._issuer = issuer
        self._audience = audience
        self._algorithm = algorithm

    def setup(self, auth: Auth) -> None:
        from urauth.methods import JWT

        if isinstance(auth.method, JWT):
            if self._access_ttl is not None:
                auth.method = JWT(
                    store=auth.method.store,
                    ttl=self._access_ttl,
                    refresh_ttl=self._refresh_ttl or auth.method.refresh_ttl,
                    issuer=self._issuer or auth.method.issuer,
                    audience=self._audience or auth.method.audience,
                )
            if self._algorithm is not None:
                auth.algorithm = self._algorithm
            if self._issuer is not None:
                auth.method = JWT(
                    store=auth.method.store,
                    ttl=auth.method.ttl,
                    refresh_ttl=auth.method.refresh_ttl,
                    issuer=self._issuer,
                    audience=self._audience or auth.method.audience,
                )

        auth.jwt = self

    @property
    def access_ttl(self) -> int | None:
        return self._access_ttl

    @property
    def refresh_ttl(self) -> int | None:
        return self._refresh_ttl
