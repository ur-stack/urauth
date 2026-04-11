"""urauth FastAPI adapter — requires ``pip install urauth[fastapi]``."""

from __future__ import annotations

import fastapi as fastapi  # ensure fastapi is installed

from urauth._version import __version__
from urauth.auth import Auth as Auth
from urauth.context import AuthContext
from urauth.fastapi.auth import FastAuth
from urauth.fastapi.transport.bearer import BearerTransport
from urauth.fastapi.transport.cookie import CookieTransport
from urauth.fastapi.transport.hybrid import HybridTransport

__all__ = [
    "Auth",
    "AuthContext",
    "BearerTransport",
    "CookieTransport",
    "FastAuth",
    "HybridTransport",
    "__version__",
]
