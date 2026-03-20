"""Password auth endpoints (login, refresh, logout)."""

from __future__ import annotations

from app.core.security.auth import auth

router = auth.password_auth_router()
