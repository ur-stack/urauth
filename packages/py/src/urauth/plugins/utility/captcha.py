"""CAPTCHA verification plugin.

Supports hCaptcha (default), reCAPTCHA v2, and reCAPTCHA v3.
Verifies tokens server-side before processing form submissions.

Requires: ``pip install httpx``

Usage::

    from urauth.plugins.utility import CaptchaPlugin

    auth = Auth(
        plugins=[
            CaptchaPlugin(
                provider="hcaptcha",
                secret_key=os.environ["HCAPTCHA_SECRET"],
            )
        ],
        ...
    )

    # In a registration handler:
    await auth.captcha.require(token, ip=request.client.host)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from urauth.auth import Auth


_VERIFY_URLS = {
    "hcaptcha": "https://hcaptcha.com/siteverify",
    "recaptcha_v2": "https://www.google.com/recaptcha/api/siteverify",
    "recaptcha_v3": "https://www.google.com/recaptcha/api/siteverify",
}


class CaptchaPlugin:
    """Server-side CAPTCHA token verification plugin.

    Verifies the token that the browser-side CAPTCHA widget generates.
    Must be called *before* processing any user-submitted form that
    you want to protect against bots.
    """

    id = "captcha"

    def __init__(
        self,
        *,
        provider: Literal["hcaptcha", "recaptcha_v2", "recaptcha_v3"] = "hcaptcha",
        secret_key: str,
        min_score: float = 0.5,
        timeout: float = 5.0,
    ) -> None:
        """
        Args:
            provider: CAPTCHA provider — ``"hcaptcha"`` (default),
                ``"recaptcha_v2"``, or ``"recaptcha_v3"``.
            secret_key: Your server-side secret key from the provider's dashboard.
            min_score: Minimum score to accept for reCAPTCHA v3 (0.0–1.0).
                       Ignored for hCaptcha and reCAPTCHA v2.
            timeout: HTTP request timeout in seconds.
        """
        if provider not in _VERIFY_URLS:
            raise ValueError(f"Unknown CAPTCHA provider: {provider!r}. Use: {list(_VERIFY_URLS)}")
        self.provider = provider
        self._secret = secret_key
        self.min_score = min_score
        self._timeout = timeout
        self._verify_url = _VERIFY_URLS[provider]

    def setup(self, auth: Auth) -> None:
        auth.captcha = self

    async def verify(self, token: str, *, ip: str | None = None) -> bool:
        """Verify a CAPTCHA *token* received from the client.

        Returns ``True`` if the token is valid (and score meets threshold for v3).

        Raises:
            ImportError: ``httpx`` is not installed.
        """
        try:
            import httpx
        except ImportError:
            raise ImportError("CaptchaPlugin requires httpx: pip install httpx") from None

        payload: dict[str, str] = {"secret": self._secret, "response": token}
        if ip:
            payload["remoteip"] = ip

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(self._verify_url, data=payload)
            response.raise_for_status()

        data = response.json()
        if not data.get("success"):
            return False

        if self.provider == "recaptcha_v3":
            score = float(data.get("score", 0.0))
            return score >= self.min_score

        return True

    async def require(self, token: str, *, ip: str | None = None) -> None:
        """Raise ``ValueError`` if the CAPTCHA token is invalid or below threshold.

        Call this at the start of handlers that receive user-submitted forms.
        """
        valid = await self.verify(token, ip=ip)
        if not valid:
            raise ValueError("CAPTCHA verification failed. Please try again.")
