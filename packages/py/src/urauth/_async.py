"""Async helpers shared across urauth."""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
from typing import Any


async def maybe_await(result: Any) -> Any:
    """Await if coroutine, return as-is otherwise."""
    if inspect.isawaitable(result):
        return await result
    return result


def run_sync(coro: Any) -> Any:
    """Run a coroutine synchronously. Works outside and inside event loops."""
    if not inspect.isawaitable(coro):
        return coro
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        return asyncio.run(coro)  # type: ignore[arg-type]

    # Inside a running loop — create a new thread to avoid deadlock
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()  # type: ignore[arg-type]
