"""Passkey / WebAuthn authentication plugin.

Passkeys require a dedicated WebAuthn library. This plugin provides the
scaffolding and interface — wire in ``py_webauthn`` (or similar) via the
``backend`` parameter.

Install: ``pip install py-webauthn``

Usage::

    import webauthn
    from urauth.plugins.authn import PasskeyPlugin

    auth = Auth(
        plugins=[
            PasskeyPlugin(
                rp_id="myapp.com",
                rp_name="My App",
                origin="https://myapp.com",
            )
        ],
        ...
    )

    # Registration
    options = await auth.passkey.registration_options(user_id="u1", username="alice")
    # ... send options to browser, get credential response ...
    await auth.passkey.verify_registration(user_id="u1", credential=cred_response)

    # Authentication
    options = await auth.passkey.authentication_options(user_id="u1")
    # ... send options to browser, get assertion response ...
    ok = await auth.passkey.verify_authentication(user_id="u1", credential=assertion)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth


class PasskeyPlugin:
    """WebAuthn / Passkey authentication.

    Requires a WebAuthn backend — the default ``backend`` expectation is
    ``py-webauthn`` (``pip install py-webauthn``), but any object implementing
    the same interface can be substituted.
    """

    id = "passkey"

    def __init__(
        self,
        *,
        rp_id: str,
        rp_name: str,
        origin: str,
        credential_store: Any = None,
        backend: Any = None,
    ) -> None:
        """
        Args:
            rp_id: Relying party domain (e.g. ``"myapp.com"``).
            rp_name: Human-readable relying party name shown in authenticators.
            origin: Full origin URL (e.g. ``"https://myapp.com"``).
            credential_store: Object for persisting credential records.
                Must implement ``save(user_id, credential)``,
                ``get(user_id, credential_id)``, ``list(user_id)``,
                ``delete(user_id, credential_id)``.
            backend: Custom WebAuthn backend. Defaults to ``py_webauthn``.
        """
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self._store = credential_store
        self._backend = backend

    def setup(self, auth: Auth) -> None:
        if self._backend is None:
            try:
                import webauthn  # type: ignore[import]

                self._backend = webauthn
            except ImportError:
                raise ImportError(
                    "PasskeyPlugin requires py-webauthn: pip install py-webauthn"
                ) from None
        auth.passkey = self

    async def registration_options(self, *, user_id: str, username: str) -> dict[str, Any]:
        """Generate WebAuthn registration options (challenge + RP info) for the browser."""
        raise NotImplementedError(
            "Implement registration_options() by calling self._backend.generate_registration_options()"
        )

    async def verify_registration(self, *, user_id: str, credential: dict[str, Any]) -> None:
        """Verify the credential created during registration and persist it."""
        raise NotImplementedError(
            "Implement verify_registration() by calling self._backend.verify_registration_response()"
        )

    async def authentication_options(self, *, user_id: str) -> dict[str, Any]:
        """Generate WebAuthn authentication options (challenge) for the browser."""
        raise NotImplementedError(
            "Implement authentication_options() by calling self._backend.generate_authentication_options()"
        )

    async def verify_authentication(self, *, user_id: str, credential: dict[str, Any]) -> bool:
        """Verify the assertion made during authentication."""
        raise NotImplementedError(
            "Implement verify_authentication() by calling self._backend.verify_authentication_response()"
        )

    async def list_credentials(self, user_id: str) -> list[dict[str, Any]]:
        """List registered passkeys for *user_id*."""
        if self._store is None:
            return []
        return await self._store.list(user_id)

    async def delete_credential(self, user_id: str, credential_id: str) -> None:
        """Remove a registered passkey."""
        if self._store is not None:
            await self._store.delete(user_id, credential_id)
