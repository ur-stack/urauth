"""API key authorization plugin.

Wraps :class:`~urauth.apikeys.manager.ApiKeyManager` and attaches it to
``auth.api_keys`` so the manager is accessible everywhere Auth is.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth
    from urauth.apikeys.manager import ApiKeyStore, CreatedApiKey, ApiKeyRecord


class ApiKeyPlugin:
    """API key creation, verification, and revocation plugin.

    Usage::

        from urauth.plugins.authz import ApiKeyPlugin

        class MyApiKeyStore:
            ...  # implement ApiKeyStore protocol

        auth = Auth(
            plugins=[ApiKeyPlugin(store=MyApiKeyStore(), prefix="sk_live")],
            ...
        )

        # Create a new key — show raw_key to the user once
        result = await auth.api_keys.create(
            user_id="u1",
            name="CI token",
            scopes=["read", "deploy"],
            expires_in=86400 * 30,
        )
        print(result.raw_key)  # "sk_live_xK3mN..."

        # Verify on each request
        record = await auth.api_keys.verify(raw_key)
        if record is None:
            raise Unauthorized

        # Revoke
        await auth.api_keys.revoke(key_id)
    """

    id = "api-key"

    def __init__(
        self,
        store: Any,
        *,
        prefix: str = "urauth",
    ) -> None:
        self._store = store
        self._prefix = prefix
        self._manager: Any = None

    def setup(self, auth: Auth) -> None:
        from urauth.apikeys.manager import ApiKeyManager

        self._manager = ApiKeyManager(self._store, prefix=self._prefix)
        auth.api_keys = self._manager

    # Delegate the full manager interface so plugin itself is usable too

    async def create(
        self,
        *,
        user_id: str,
        name: str,
        scopes: list[str] | None = None,
        expires_in: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CreatedApiKey:
        assert self._manager is not None
        return await self._manager.create(
            user_id=user_id, name=name, scopes=scopes, expires_in=expires_in, metadata=metadata
        )

    async def verify(self, raw_key: str) -> ApiKeyRecord | None:
        assert self._manager is not None
        return await self._manager.verify(raw_key)

    async def revoke(self, key_id: str) -> None:
        assert self._manager is not None
        await self._manager.revoke(key_id)

    async def list_for_user(self, user_id: str) -> list[ApiKeyRecord]:
        assert self._manager is not None
        return await self._manager.list_for_user(user_id)
