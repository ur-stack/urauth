"""One-Time Token plugin.

Issues single-use signed tokens for operations like email verification,
password reset confirmation, or any action that should only be completable once.

Built on itsdangerous — same signing approach as :class:`~urauth.account.tokens.AccountTokens`
but with configurable per-purpose salts and optional DB-side consumption tracking.

Usage::

    from urauth.plugins.utility import OneTimeTokenPlugin

    auth = Auth(
        plugins=[OneTimeTokenPlugin()],
        ...
    )

    # Issue a one-time token
    token = auth.one_time_token.issue("verify-email", payload="user@example.com")

    # Consume it (raises ValueError if invalid/expired/already used)
    payload = await auth.one_time_token.consume("verify-email", token)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth


class OneTimeTokenPlugin:
    """Single-use signed tokens with per-purpose salts.

    Each ``purpose`` gets its own itsdangerous salt, preventing tokens issued
    for one purpose from being reused for another.

    Token consumption is tracked in-memory by default. For production, provide
    a ``store`` implementing ``mark_used(jti: str) -> bool`` (returns True if
    first use, False if already consumed).
    """

    id = "one-time-token"

    def __init__(
        self,
        *,
        store: Any = None,
        default_ttl: int = 3600,
        namespace: str = "urauth.ott",
    ) -> None:
        """
        Args:
            store: Optional persistent store for tracking consumed tokens.
                   Must implement ``async mark_used(jti: str) -> bool``.
                   Defaults to an in-memory set (not suitable for multi-process).
            default_ttl: Default token lifetime in seconds (default: 1 hour).
            namespace: Salt prefix to prevent cross-purpose token reuse.
        """
        self._store = store
        self._default_ttl = default_ttl
        self._namespace = namespace
        self._used: set[str] = set()  # in-memory fallback
        self._signers: dict[str, Any] = {}

    def setup(self, auth: Auth) -> None:
        self._secret = auth.secret_key
        auth.one_time_token = self

    def _signer(self, purpose: str) -> Any:
        if purpose not in self._signers:
            from itsdangerous import URLSafeTimedSerializer

            self._signers[purpose] = URLSafeTimedSerializer(
                self._secret, salt=f"{self._namespace}.{purpose}"
            )
        return self._signers[purpose]

    def issue(self, purpose: str, payload: str, *, ttl: int | None = None) -> str:
        """Issue a one-time token for *purpose* encoding *payload*.

        The *ttl* (seconds) is enforced on consume, not at issue time.
        """
        import uuid

        jti = uuid.uuid4().hex
        # Embed the jti in the payload so we can track consumption
        return self._signer(purpose).dumps(f"{jti}:{payload}")

    async def consume(self, purpose: str, token: str, *, max_age: int | None = None) -> str:
        """Verify and consume a one-time token. Returns the original *payload*.

        Raises:
            ValueError: Token is invalid, expired, or already consumed.
        """
        from itsdangerous import BadSignature, SignatureExpired

        age = max_age if max_age is not None else self._default_ttl
        try:
            raw: str = self._signer(purpose).loads(token, max_age=age)
        except SignatureExpired as exc:
            raise ValueError("Token has expired.") from exc
        except BadSignature as exc:
            raise ValueError("Invalid token.") from exc

        jti, _, payload = raw.partition(":")
        # Check + mark used
        if self._store is not None:
            first_use = await self._store.mark_used(jti)
            if not first_use:
                raise ValueError("Token has already been used.")
        else:
            if jti in self._used:
                raise ValueError("Token has already been used.")
            self._used.add(jti)

        return payload
