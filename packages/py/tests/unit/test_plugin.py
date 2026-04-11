"""Tests for the urauth plugin system."""

from __future__ import annotations

import pytest

from urauth import Auth, JWT, UrAuthPlugin
from urauth.plugin import PluginRegistry
from urauth.storage.memory import MemoryTokenStore


# ── Helpers ──────────────────────────────────────────────────────


def make_auth(**kwargs):
    if "method" not in kwargs:
        kwargs["method"] = JWT(store=MemoryTokenStore())
    return Auth(
        secret_key="supersecretkeyfortest-at-least-32-chars",
        allow_insecure_key=True,
        environment="testing",
        **kwargs,
    )


# ── Protocol compliance ───────────────────────────────────────────


class MinimalPlugin:
    id = "minimal"

    def setup(self, auth):
        pass


class HookPlugin:
    id = "hooks"

    def __init__(self):
        self.logins: list[dict] = []
        self.failures: list[str] = []
        self.logouts: list[str] = []
        self.refreshes: list[str] = []
        self.contexts: list[object] = []
        self.setup_called = False

    def setup(self, auth):
        self.setup_called = True
        self.auth = auth

    async def on_login(self, user_id: str, method: str) -> None:
        self.logins.append({"user_id": user_id, "method": method})

    async def on_login_failed(self, identifier: str) -> None:
        self.failures.append(identifier)

    async def on_logout(self, user_id: str) -> None:
        self.logouts.append(user_id)

    async def on_token_refresh(self, user_id: str) -> None:
        self.refreshes.append(user_id)

    async def on_context_built(self, context: object) -> None:
        self.contexts.append(context)


class SyncHookPlugin:
    """Plugin with sync (non-async) hook implementations."""

    id = "sync_hooks"

    def __init__(self):
        self.events: list[str] = []

    def on_login(self, user_id: str, method: str) -> None:
        self.events.append(f"login:{user_id}:{method}")

    def on_logout(self, user_id: str) -> None:
        self.events.append(f"logout:{user_id}")


# ── Tests ─────────────────────────────────────────────────────────


def test_urauth_plugin_protocol():
    """MinimalPlugin satisfies the UrAuthPlugin runtime-checkable Protocol."""
    assert isinstance(MinimalPlugin(), UrAuthPlugin)


def test_plugin_registry_len():
    registry = PluginRegistry([MinimalPlugin(), HookPlugin()])
    assert len(registry) == 2


def test_plugin_registry_bool():
    assert not PluginRegistry([])
    assert PluginRegistry([MinimalPlugin()])


def test_plugin_registry_get():
    p = HookPlugin()
    registry = PluginRegistry([p])
    assert registry.get("hooks") is p
    assert registry.get("nonexistent") is None


def test_setup_called_during_auth_init():
    plugin = HookPlugin()
    auth = make_auth(plugins=[plugin])
    assert plugin.setup_called
    assert plugin.auth is auth


def test_auth_plugins_attribute():
    plugin = MinimalPlugin()
    auth = make_auth(plugins=[plugin])
    assert isinstance(auth.plugins, PluginRegistry)
    assert len(auth.plugins) == 1


def test_auth_no_plugins_is_empty_registry():
    auth = make_auth()
    assert isinstance(auth.plugins, PluginRegistry)
    assert not auth.plugins


@pytest.mark.asyncio
async def test_on_login_emitted():
    plugin = HookPlugin()
    USERS = {"u1": type("U", (), {"id": "u1", "is_active": True})()}

    auth = make_auth(
        plugins=[plugin],
        get_user=lambda uid: USERS.get(uid),
        get_user_by_username=lambda u: USERS.get(u),
        verify_password=lambda user, pw: pw == "correct",
    )

    await auth.login("u1", "correct")
    assert len(plugin.logins) == 1
    assert plugin.logins[0]["user_id"] == "u1"
    assert plugin.logins[0]["method"] == "password"


@pytest.mark.asyncio
async def test_on_login_failed_emitted_bad_password():
    plugin = HookPlugin()
    USERS = {"u1": type("U", (), {"id": "u1", "is_active": True})()}

    auth = make_auth(
        plugins=[plugin],
        get_user=lambda uid: USERS.get(uid),
        get_user_by_username=lambda u: USERS.get(u),
        verify_password=lambda user, pw: pw == "correct",
    )

    from urauth.exceptions import UnauthorizedError

    with pytest.raises(UnauthorizedError):
        await auth.login("u1", "wrong")

    assert plugin.failures == ["u1"]
    assert plugin.logins == []


@pytest.mark.asyncio
async def test_on_login_failed_emitted_unknown_user():
    plugin = HookPlugin()

    auth = make_auth(
        plugins=[plugin],
        get_user=lambda uid: None,
        get_user_by_username=lambda u: None,
        verify_password=lambda user, pw: True,
    )

    from urauth.exceptions import UnauthorizedError

    with pytest.raises(UnauthorizedError):
        await auth.login("ghost@example.com", "any")

    assert plugin.failures == ["ghost@example.com"]


@pytest.mark.asyncio
async def test_on_logout_emitted():
    plugin = HookPlugin()
    store = MemoryTokenStore()
    auth = make_auth(plugins=[plugin], method=JWT(store=store))

    from urauth.tokens.lifecycle import IssueRequest

    issued = await auth.lifecycle.issue(IssueRequest(user_id="u1"))
    await auth.logout(issued.access_token)

    assert "u1" in plugin.logouts


@pytest.mark.asyncio
async def test_sync_hooks_work():
    """Sync hook implementations are transparently awaited."""
    plugin = SyncHookPlugin()
    store = MemoryTokenStore()
    auth = make_auth(plugins=[plugin], method=JWT(store=store))

    from urauth.tokens.lifecycle import IssueRequest

    issued = await auth.lifecycle.issue(IssueRequest(user_id="u42"))
    await auth.logout(issued.access_token)

    assert "logout:u42" in plugin.events


@pytest.mark.asyncio
async def test_multiple_plugins_all_receive_hooks():
    plugin_a = HookPlugin()
    plugin_a.id = "a"
    plugin_b = HookPlugin()
    plugin_b.id = "b"

    USERS = {"usr": type("U", (), {"id": "usr", "is_active": True})()}
    auth = make_auth(
        plugins=[plugin_a, plugin_b],
        get_user=lambda uid: USERS.get(uid),
        get_user_by_username=lambda u: USERS.get(u),
        verify_password=lambda user, pw: True,
    )

    await auth.login("usr", "pw")
    assert len(plugin_a.logins) == 1
    assert len(plugin_b.logins) == 1


@pytest.mark.asyncio
async def test_on_token_refresh_emitted():
    plugin = HookPlugin()
    store = MemoryTokenStore()
    auth = make_auth(plugins=[plugin], method=JWT(store=store))

    from urauth.tokens.lifecycle import IssueRequest

    issued = await auth.lifecycle.issue(IssueRequest(user_id="u99"))
    await auth.refresh_tokens(issued.refresh_token)

    assert "u99" in plugin.refreshes


def test_plugin_setup_can_mutate_auth():
    """Plugins can wire event handlers or override config during setup."""

    class ConfigPlugin:
        id = "config"

        def setup(self, auth):
            auth._injected_by_plugin = True

    plugin = ConfigPlugin()
    auth = make_auth(plugins=[plugin])
    assert getattr(auth, "_injected_by_plugin", False) is True
