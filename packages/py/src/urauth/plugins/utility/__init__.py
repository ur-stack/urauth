"""Utility plugins for urauth.

Cross-cutting concerns that augment any authentication setup.
"""

from urauth.plugins.utility.captcha import CaptchaPlugin
from urauth.plugins.utility.device_authorization import (
    DeviceAuthorizationPlugin,
    DeviceSession,
    DeviceStartResult,
    DeviceStore,
)
from urauth.plugins.utility.hibp import HibpPlugin
from urauth.plugins.utility.jwt_config import JWTPlugin
from urauth.plugins.utility.last_login import LastLoginPlugin, LastLoginStore, LoginRecord
from urauth.plugins.utility.multi_session import MultiSessionPlugin, SessionRecord, SessionTracker
from urauth.plugins.utility.one_time_token import OneTimeTokenPlugin

__all__ = [
    "CaptchaPlugin",
    "DeviceAuthorizationPlugin",
    "DeviceSession",
    "DeviceStartResult",
    "DeviceStore",
    "HibpPlugin",
    "JWTPlugin",
    "LastLoginPlugin",
    "LastLoginStore",
    "LoginRecord",
    "MultiSessionPlugin",
    "OneTimeTokenPlugin",
    "SessionRecord",
    "SessionTracker",
]
