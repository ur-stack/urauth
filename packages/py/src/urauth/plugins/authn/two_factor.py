"""Two-factor authentication plugin.

Combines TOTP, backup codes, and step-up tokens into a single composable
plugin. The primitives (TOTP, BackupCodes, StepUpToken) live in
``urauth.mfa``; this plugin wires them together and attaches them to Auth.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth
    from urauth.mfa.backup_codes import BackupCodeStore, GeneratedCodes
    from urauth.mfa.totp import TOTP


class TwoFactorPlugin:
    """TOTP + backup codes + step-up tokens as a single plugin.

    Usage::

        from urauth.plugins.authn import TwoFactorPlugin
        from urauth.mfa import BackupCodes

        class MyBackupStore:
            ...  # implement BackupCodeStore protocol

        auth = Auth(
            plugins=[
                TwoFactorPlugin(
                    backup_code_store=MyBackupStore(),
                    step_up_ttl=300,
                )
            ],
            ...
        )

        # Enroll a user — returns provisioning URI for QR code
        uri = auth.two_factor.enroll_totp(user_id="u1", issuer="MyApp")

        # Verify TOTP code on login
        ok = auth.two_factor.verify_totp(user_id="u1", secret=stored_secret, code="123456")

        # Issue a step-up token after MFA verification
        step_up = auth.two_factor.issue_step_up("u1", context="change_password")

        # Verify step-up token at protected endpoint
        uid = auth.two_factor.verify_step_up(step_up, context="change_password")

        # Generate backup codes
        result = await auth.two_factor.generate_backup_codes("u1")
        # Show result.codes to the user once

        # Consume a backup code
        ok = await auth.two_factor.consume_backup_code("u1", code="ab12-cd34")
    """

    id = "two-factor"

    def __init__(
        self,
        *,
        backup_code_store: BackupCodeStore | None = None,
        step_up_ttl: int = 300,
        totp_digits: int = 6,
        totp_period: int = 30,
        totp_algorithm: str = "sha1",
        totp_window: int = 1,
        backup_code_count: int = 10,
    ) -> None:
        self._backup_store = backup_code_store
        self._step_up_ttl = step_up_ttl
        self._totp_digits = totp_digits
        self._totp_period = totp_period
        self._totp_algorithm = totp_algorithm
        self._totp_window = totp_window
        self._backup_code_count = backup_code_count

        self._step_up: Any = None
        self._backup_codes: Any = None

    def setup(self, auth: Auth) -> None:
        from urauth.mfa.step_up import StepUpToken

        self._step_up = StepUpToken(auth.secret_key, max_age=self._step_up_ttl)
        if self._backup_store is not None:
            from urauth.mfa.backup_codes import BackupCodes

            self._backup_codes = BackupCodes(self._backup_store)

        auth.two_factor = self

    # ── TOTP ─────────────────────────────────────────────────────────────────

    def new_totp(self, *, issuer: str = "urauth") -> TOTP:
        """Create a :class:`~urauth.mfa.totp.TOTP` instance with a fresh secret.

        Returns the TOTP object — store ``totp.b32_secret`` (str) encrypted
        per-user in your database, then reconstruct with :meth:`totp_for`.
        """
        from urauth.mfa.totp import TOTP

        secret = TOTP.generate_secret()
        return TOTP(
            secret,
            digits=self._totp_digits,
            period=self._totp_period,
            algorithm=self._totp_algorithm,
            window=self._totp_window,
            issuer=issuer,
        )

    def totp_for(self, b32_secret: str, *, issuer: str = "urauth") -> TOTP:
        """Create a :class:`~urauth.mfa.totp.TOTP` instance from a stored Base32 secret."""
        from urauth.mfa.totp import TOTP

        return TOTP(
            b32_secret,
            digits=self._totp_digits,
            period=self._totp_period,
            algorithm=self._totp_algorithm,
            window=self._totp_window,
            issuer=issuer,
        )

    def provisioning_uri(
        self,
        b32_secret: str,
        *,
        issuer: str,
        account_name: str = "",
    ) -> str:
        """Return an ``otpauth://`` URI for QR code generation."""
        return self.totp_for(b32_secret, issuer=issuer).provisioning_uri(account_name=account_name)

    def verify_totp(self, b32_secret: str, code: str, *, at: float | None = None) -> bool:
        """Return ``True`` if *code* is valid for the given *b32_secret* at time *at*."""
        return self.totp_for(b32_secret).verify(code, at=at)

    # ── Step-up tokens ────────────────────────────────────────────────────────

    def issue_step_up(self, user_id: str, *, context: str = "") -> str:
        """Issue a short-lived step-up token after successful MFA verification."""
        assert self._step_up is not None, "TwoFactorPlugin.setup() was not called"
        return self._step_up.issue(user_id, context=context)

    def verify_step_up(self, token: str, *, context: str = "") -> str:
        """Verify a step-up token and return the ``user_id``.

        Raises ``ValueError`` if the token is invalid, expired, or the
        context does not match.
        """
        assert self._step_up is not None, "TwoFactorPlugin.setup() was not called"
        return self._step_up.verify(token, context=context)

    # ── Backup codes ──────────────────────────────────────────────────────────

    async def generate_backup_codes(self, user_id: str) -> GeneratedCodes:
        """Generate and store a fresh set of backup codes for *user_id*.

        The returned ``GeneratedCodes.codes`` must be shown to the user exactly
        once — they are not stored in plaintext.

        Raises ``RuntimeError`` if the plugin was created without a ``backup_code_store``.
        """
        if self._backup_codes is None:
            raise RuntimeError(
                "TwoFactorPlugin requires a backup_code_store to manage backup codes."
            )
        return await self._backup_codes.generate(user_id, count=self._backup_code_count)

    async def consume_backup_code(self, user_id: str, code: str) -> bool:
        """Consume a single-use backup code. Returns ``True`` on success."""
        if self._backup_codes is None:
            raise RuntimeError(
                "TwoFactorPlugin requires a backup_code_store to manage backup codes."
            )
        return await self._backup_codes.consume(user_id, code)

    async def remaining_backup_codes(self, user_id: str) -> int:
        """Return the number of unused backup codes remaining for *user_id*."""
        if self._backup_codes is None:
            return 0
        return await self._backup_codes.remaining_count(user_id)
