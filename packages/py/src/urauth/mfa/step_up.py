"""Step-up authentication tokens.

A step-up token is a short-lived, signed proof that a user has *just*
completed a second factor. Endpoints that require elevated trust (e.g.
changing a password, approving a transfer) check for a valid step-up token
rather than re-running the full MFA flow on every request.

Built on itsdangerous — same signing approach as magic links and reset tokens,
no extra dependency.
"""

from __future__ import annotations

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class StepUpToken:
    """Issue and verify short-lived step-up tokens.

    Args:
        secret_key: The application secret key.
        max_age: Token lifetime in seconds (default: 5 minutes). Keep short —
                 step-up tokens prove *recent* second-factor completion.

    Usage::

        step_up = StepUpToken(secret_key=settings.secret_key, max_age=300)

        # After successful MFA verification
        token = step_up.issue(user_id="usr_123", context="change_password")

        # At the protected endpoint
        try:
            user_id = step_up.verify(token, context="change_password")
        except ValueError:
            raise HTTPException(403, "Step-up required")
    """

    def __init__(self, secret_key: str, max_age: int = 300) -> None:
        self._max_age = max_age
        self._signer = URLSafeTimedSerializer(secret_key, salt="urauth.step_up")

    def issue(self, user_id: str, *, context: str = "") -> str:
        """Return a signed step-up token for *user_id*.

        Args:
            user_id: The authenticated user.
            context: Optional operation name (e.g. ``"change_password"``).
                     Verified tokens must present the same context.
        """
        payload = f"{user_id}:{context}" if context else user_id
        return self._signer.dumps(payload)

    def verify(self, token: str, *, context: str = "", max_age: int | None = None) -> str:
        """Verify *token* and return the user_id.

        Args:
            token: The step-up token presented by the client.
            context: Must match the context used when issuing.
            max_age: Override the default lifetime for this check.

        Raises:
            ValueError: Token is invalid, expired, or context mismatch.
        """
        age = max_age if max_age is not None else self._max_age
        try:
            payload: str = self._signer.loads(token, max_age=age)
        except SignatureExpired as exc:
            raise ValueError("Step-up token has expired") from exc
        except BadSignature as exc:
            raise ValueError("Invalid step-up token") from exc

        has_context = ":" in payload

        if context:
            if not has_context:
                raise ValueError("Step-up token context mismatch")
            user_id, token_context = payload.split(":", 1)
            if token_context != context:
                raise ValueError("Step-up token context mismatch")
            return user_id

        # No context expected — reject tokens that were issued with one.
        if has_context:
            raise ValueError("Step-up token context mismatch")
        return payload
