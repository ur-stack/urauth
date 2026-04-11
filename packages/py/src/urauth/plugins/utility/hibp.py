"""Have I Been Pwned (HIBP) password breach detection plugin.

Uses the k-anonymity API — only the first 5 characters of the SHA-1 hash
are sent to the API. The full password never leaves the server.

Requires: ``pip install httpx`` (already an optional dep via ``urauth[oauth]``).

Usage::

    from urauth.plugins.utility import HibpPlugin

    auth = Auth(
        plugins=[HibpPlugin(reject_compromised=True, min_breach_count=1)],
        ...
    )

    # In a registration or password-change handler:
    await auth.hibp.validate(new_password)  # raises ValueError if compromised
    count = await auth.hibp.check(new_password)  # returns breach count
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from urauth.auth import Auth


class HibpPlugin:
    """Password breach detection via the Have I Been Pwned k-anonymity API.

    The password is hashed with SHA-1 locally. Only the first 5 hex characters
    (the "prefix") are sent to the HIBP API — the suffix stays on your server.
    The API returns all matching hash suffixes; we check ours locally.
    This guarantees the full password is never transmitted.
    """

    id = "hibp"

    def __init__(
        self,
        *,
        reject_compromised: bool = True,
        min_breach_count: int = 1,
        api_url: str = "https://api.pwnedpasswords.com/range/",
        timeout: float = 5.0,
    ) -> None:
        """
        Args:
            reject_compromised: If ``True`` (default), :meth:`validate` raises
                ``ValueError`` for any breached password.
            min_breach_count: Minimum breach count to consider a password compromised
                (default 1 — any appearance in a data breach).
            api_url: HIBP range API URL. Override for self-hosted instances.
            timeout: HTTP request timeout in seconds.
        """
        self.reject_compromised = reject_compromised
        self.min_breach_count = min_breach_count
        self._api_url = api_url
        self._timeout = timeout

    def setup(self, auth: Auth) -> None:
        auth.hibp = self

    async def check(self, password: str) -> int:
        """Return the number of times *password* has appeared in known data breaches.

        Returns ``0`` if the password has not been found.

        Raises:
            ImportError: ``httpx`` is not installed.
            httpx.HTTPError: API request failed.
        """
        import hashlib

        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        try:
            import httpx
        except ImportError:
            raise ImportError(
                "HibpPlugin requires httpx: pip install httpx  (or pip install urauth[oauth])"
            ) from None

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(f"{self._api_url}{prefix}")
            response.raise_for_status()

        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                return int(parts[1])
        return 0

    async def validate(self, password: str) -> None:
        """Raise ``ValueError`` if *password* is found in known data breaches.

        Call this in registration and password-change handlers *before* hashing.

        Raises:
            ValueError: Password appears in *min_breach_count* or more breaches.
            ImportError: ``httpx`` is not installed.
        """
        if not self.reject_compromised:
            return
        count = await self.check(password)
        if count >= self.min_breach_count:
            raise ValueError(
                f"This password has appeared in {count:,} known data breach"
                + ("es" if count != 1 else "")
                + ". Please choose a different password."
            )
