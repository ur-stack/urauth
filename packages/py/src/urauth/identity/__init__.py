"""Identity & Auth layer — password, OTP, magic links, passkeys."""

from urauth.identity.password import PasswordHasher

__all__ = ["PasswordHasher"]
