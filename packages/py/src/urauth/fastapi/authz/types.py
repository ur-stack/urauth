"""Starlette-typed SubjectResolver for FastAPI adapter."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.requests import Request

SubjectResolver = Callable[[Request], Any] | Callable[[Request], Awaitable[Any]]
