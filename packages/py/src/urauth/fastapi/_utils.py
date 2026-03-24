"""Shared FastAPI utilities — single source of truth for common helpers."""

from __future__ import annotations

import inspect
import typing
from collections.abc import Callable
from typing import Any

from starlette.requests import Request

from urauth.context import AuthContext


def find_request_param(func: Callable[..., Any]) -> str | None:
    """Find the parameter annotated as Request in a function signature."""
    try:
        hints = typing.get_type_hints(func)
    except Exception:
        hints = {}
    sig = inspect.signature(func)
    for name in sig.parameters:
        hint = hints.get(name, sig.parameters[name].annotation)
        if hint is Request or (isinstance(hint, type) and issubclass(hint, Request)):
            return name
        if isinstance(hint, str) and hint in ("Request", "starlette.requests.Request"):
            return name
    return None


def find_context_and_request(
    sig: inspect.Signature,
    request_param: str | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> tuple[AuthContext | None, Request | None]:
    """Extract AuthContext and Request from function call arguments."""
    request: Request | None = None
    if request_param is not None:
        request = kwargs.get(request_param)  # type: ignore[assignment]
        if request is None:
            param_names = list(sig.parameters.keys())
            try:
                idx = param_names.index(request_param)
                if idx < len(args):
                    request = args[idx]  # type: ignore[assignment]
            except ValueError:
                pass

    ctx: AuthContext | None = None
    for v in kwargs.values():
        if request is None and isinstance(v, Request):
            request = v  # type: ignore[reportUnknownVariableType]
        if isinstance(v, AuthContext):
            ctx = v
            if request is None and v.request is not None:
                request = v.request

    return ctx, request
