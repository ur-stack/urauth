"""urauth plugin system.

Plugins are composable, self-contained units that extend Auth behaviour
without requiring subclassing. Each plugin declares an ``id`` and a
``setup()`` method, and can optionally implement lifecycle hooks.

Usage::

    from urauth import Auth, JWT
    from urauth.plugin import UrAuthPlugin

    class MyAuditPlugin:
        id = "audit"

        def setup(self, auth):
            # Wire up event handler, override hooks, etc.
            from urauth.audit.events import StructlogEventHandler
            auth._event_handler = StructlogEventHandler()

        async def on_login(self, user_id: str, method: str) -> None:
            print(f"Login: user={user_id} via {method}")

        async def on_logout(self, user_id: str) -> None:
            print(f"Logout: user={user_id}")

    auth = Auth(
        plugins=[MyAuditPlugin()],
        method=JWT(),
        secret_key="...",
    )

Lifecycle hooks (all optional, sync or async):

- ``setup(auth)``              — called once at the end of ``Auth.__init__``
- ``on_login(user_id, method)``        — after successful credential verification
- ``on_login_failed(identifier)``      — after failed login attempt
- ``on_logout(user_id)``               — after token revocation
- ``on_token_refresh(user_id)``        — after token rotation
- ``on_token_revoked(user_id, jti)``   — after individual token revocation
- ``on_context_built(context)``        — after AuthContext assembly
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from urauth.auth import Auth
    from urauth.context import AuthContext


@runtime_checkable
class UrAuthPlugin(Protocol):
    """Protocol that all urauth plugins must satisfy.

    Only ``id`` is required. All lifecycle hooks are optional — the plugin
    system checks for their existence at call time via ``hasattr``.
    """

    id: str

    def setup(self, auth: Auth) -> None:
        """Called once at the end of ``Auth.__init__`` with the fully
        configured ``Auth`` instance.

        Use this to wire event handlers, override defaults, or store a
        reference to ``auth`` for use in hooks.
        """
        ...


class PluginRegistry:
    """Manages a list of plugins and dispatches lifecycle events.

    Used internally by ``Auth``. Not intended for direct use.
    """

    def __init__(self, plugins: list[Any]) -> None:
        self._plugins = plugins
        # Build fast-lookup sets so we don't call hasattr on every request
        self._has: dict[str, list[Any]] = {}
        _hooks = (
            "on_login",
            "on_login_failed",
            "on_logout",
            "on_token_refresh",
            "on_token_revoked",
            "on_context_built",
        )
        for hook in _hooks:
            self._has[hook] = [p for p in plugins if hasattr(p, hook)]

    def setup_all(self, auth: Auth) -> None:
        """Call ``setup()`` on every registered plugin."""
        for plugin in self._plugins:
            if hasattr(plugin, "setup"):
                plugin.setup(auth)

    async def emit(self, hook: str, /, **kwargs: Any) -> None:
        """Dispatch a lifecycle hook to all plugins that implement it.

        Both sync and async implementations are supported.
        """
        from urauth._async import maybe_await

        for plugin in self._has.get(hook, []):
            fn = getattr(plugin, hook)
            await maybe_await(fn(**kwargs))

    def __len__(self) -> int:
        return len(self._plugins)

    def __bool__(self) -> bool:
        return bool(self._plugins)

    def get(self, plugin_id: str) -> Any | None:
        """Return the first plugin with the given ``id``, or ``None``."""
        return next((p for p in self._plugins if getattr(p, "id", None) == plugin_id), None)
