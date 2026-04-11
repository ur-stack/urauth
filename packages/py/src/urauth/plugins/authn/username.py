"""Username + password authentication plugin."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth


@dataclass
class PasswordPolicy:
    """Declarative password strength requirements."""

    min_length: int = 8
    max_length: int = 128
    require_lowercase: bool = False
    require_uppercase: bool = False
    require_digit: bool = False
    require_special: bool = False
    forbidden: list[str] = field(default_factory=list)

    def validate(self, password: str) -> list[str]:
        """Return a list of policy violations (empty list = password is valid)."""
        errors: list[str] = []
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters.")
        if len(password) > self.max_length:
            errors.append(f"Password must be at most {self.max_length} characters.")
        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter.")
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter.")
        if self.require_digit and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit.")
        if self.require_special and not any(not c.isalnum() for c in password):
            errors.append("Password must contain at least one special character.")
        for forbidden in self.forbidden:
            if forbidden.lower() in password.lower():
                errors.append("Password contains a forbidden word.")
                break
        return errors

    def enforce(self, password: str) -> None:
        """Raise ``ValueError`` if *password* violates the policy."""
        errors = self.validate(password)
        if errors:
            raise ValueError("; ".join(errors))


class UsernamePlugin:
    """Username + password authentication plugin.

    Attaches a :class:`PasswordPolicy` and a configured
    :class:`~urauth.identity.password.PasswordHasher` to the ``Auth`` instance.
    Access them via ``auth.username_plugin``.

    Usage::

        from urauth import Auth, JWT
        from urauth.plugins.authn import UsernamePlugin

        auth = Auth(
            plugins=[
                UsernamePlugin(
                    policy=PasswordPolicy(
                        min_length=12,
                        require_digit=True,
                        require_special=True,
                    )
                )
            ],
            method=JWT(...),
            secret_key="...",
        )

        # Validate a password before hashing
        auth.username_plugin.policy.enforce(new_password)
    """

    id = "username"

    def __init__(
        self,
        *,
        policy: PasswordPolicy | None = None,
        hasher_n: int = 2**14,
        hasher_r: int = 8,
        hasher_p: int = 1,
    ) -> None:
        self.policy: PasswordPolicy = policy or PasswordPolicy()
        self._hasher_n = hasher_n
        self._hasher_r = hasher_r
        self._hasher_p = hasher_p

    def setup(self, auth: Auth) -> None:
        from urauth.identity.password import PasswordHasher

        auth.password_hasher = PasswordHasher(n=self._hasher_n, r=self._hasher_r, p=self._hasher_p)
        auth.username_plugin = self

    def hash(self, password: str) -> str:
        """Hash *password* using the configured hasher (set after ``setup()``)."""
        return self._hasher.hash(password)

    def verify(self, password: str, hashed: str) -> bool:
        """Verify *password* against a stored hash."""
        return self._hasher.verify(password, hashed)

    def _attach_hasher(self, auth: Any) -> None:
        from urauth.identity.password import PasswordHasher

        self._hasher = PasswordHasher(n=self._hasher_n, r=self._hasher_r, p=self._hasher_p)
        auth.password_hasher = self._hasher
