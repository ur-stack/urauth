"""Authentication plugins for urauth.

Each plugin handles one way users prove their identity.
"""

from urauth.plugins.authn.anonymous import AnonymousPlugin
from urauth.plugins.authn.email_otp import EmailOTPPlugin
from urauth.plugins.authn.magic_link import MagicLinkPlugin
from urauth.plugins.authn.oauth import OAuthPlugin
from urauth.plugins.authn.passkey import PasskeyPlugin
from urauth.plugins.authn.phone_number import PhoneNumberPlugin
from urauth.plugins.authn.two_factor import TwoFactorPlugin
from urauth.plugins.authn.username import PasswordPolicy, UsernamePlugin

__all__ = [
    "AnonymousPlugin",
    "EmailOTPPlugin",
    "MagicLinkPlugin",
    "OAuthPlugin",
    "PasskeyPlugin",
    "PasswordPolicy",
    "PhoneNumberPlugin",
    "TwoFactorPlugin",
    "UsernamePlugin",
]
