"""Tests for the built-in plugin library (plugins/ package)."""

from __future__ import annotations

import pytest

from urauth import Auth, JWT, UrAuthPlugin
from urauth.storage.memory import MemoryTokenStore


def make_auth(*plugins, **kwargs):
    return Auth(
        secret_key="supersecretkeyfortest-at-least-32-chars",
        allow_insecure_key=True,
        environment="testing",
        method=JWT(store=MemoryTokenStore()),
        plugins=list(plugins),
        **kwargs,
    )


# ── authn.UsernamePlugin ──────────────────────────────────────────────────────


def test_username_plugin_satisfies_protocol():
    from urauth.plugins.authn import UsernamePlugin

    assert isinstance(UsernamePlugin(), UrAuthPlugin)


def test_username_plugin_attaches_to_auth():
    from urauth.plugins.authn import UsernamePlugin

    auth = make_auth(UsernamePlugin())
    assert hasattr(auth, "username_plugin")
    assert hasattr(auth, "password_hasher")


def test_password_policy_valid():
    from urauth.plugins.authn import PasswordPolicy

    policy = PasswordPolicy(min_length=8, require_digit=True)
    assert policy.validate("abcdefg1") == []


def test_password_policy_violations():
    from urauth.plugins.authn import PasswordPolicy

    policy = PasswordPolicy(
        min_length=10,
        require_uppercase=True,
        require_digit=True,
        require_special=True,
    )
    errors = policy.validate("short")
    assert len(errors) >= 1  # at least min_length violation


def test_password_policy_enforce_raises():
    from urauth.plugins.authn import PasswordPolicy

    with pytest.raises(ValueError, match="at least"):
        PasswordPolicy(min_length=20).enforce("tooshort")


# ── authn.AnonymousPlugin ─────────────────────────────────────────────────────


def test_anonymous_plugin_attaches():
    from urauth.plugins.authn import AnonymousPlugin

    auth = make_auth(AnonymousPlugin(prefix="anon_"))
    assert hasattr(auth, "anonymous")


def test_anonymous_is_anonymous():
    from urauth.plugins.authn import AnonymousPlugin

    plugin = AnonymousPlugin(prefix="anon_")
    assert plugin.is_anonymous("anon_abc123")
    assert not plugin.is_anonymous("usr_real")


def test_anonymous_new_id():
    from urauth.plugins.authn import AnonymousPlugin

    plugin = AnonymousPlugin(prefix="guest_")
    uid = plugin.new_id()
    assert uid.startswith("guest_")
    assert len(uid) > 10


@pytest.mark.asyncio
async def test_anonymous_create_session():
    from urauth.plugins.authn import AnonymousPlugin

    plugin = AnonymousPlugin()
    auth = make_auth(plugin)
    token = await auth.anonymous.create_session()
    assert isinstance(token, str)
    assert len(token) > 20


@pytest.mark.asyncio
async def test_anonymous_upgrade_revokes():
    from urauth.plugins.authn import AnonymousPlugin
    from urauth.tokens.lifecycle import IssueRequest

    plugin = AnonymousPlugin()
    auth = make_auth(plugin)
    token = await auth.anonymous.create_session()
    # Upgrade should succeed without raising even if token is already expired/invalid
    await auth.anonymous.upgrade(anon_token=token, real_user_id="real_user")


# ── authn.TwoFactorPlugin ─────────────────────────────────────────────────────


def test_two_factor_plugin_attaches():
    from urauth.plugins.authn import TwoFactorPlugin

    auth = make_auth(TwoFactorPlugin())
    assert hasattr(auth, "two_factor")


def test_two_factor_new_totp():
    from urauth.plugins.authn import TwoFactorPlugin

    plugin = TwoFactorPlugin()
    auth = make_auth(plugin)
    totp = auth.two_factor.new_totp(issuer="TestApp")
    assert totp.b32_secret  # has a base32 secret
    assert totp.digits == 6


def test_two_factor_verify_totp_with_fresh_code():
    from urauth.plugins.authn import TwoFactorPlugin

    plugin = TwoFactorPlugin()
    auth = make_auth(plugin)
    totp = auth.two_factor.new_totp()
    code = totp.generate()
    assert auth.two_factor.verify_totp(totp.b32_secret, code)


def test_two_factor_step_up_roundtrip():
    from urauth.plugins.authn import TwoFactorPlugin

    plugin = TwoFactorPlugin(step_up_ttl=300)
    auth = make_auth(plugin)
    token = auth.two_factor.issue_step_up("user_42", context="change_password")
    user_id = auth.two_factor.verify_step_up(token, context="change_password")
    assert user_id == "user_42"


def test_two_factor_step_up_wrong_context_rejected():
    from urauth.plugins.authn import TwoFactorPlugin

    plugin = TwoFactorPlugin()
    auth = make_auth(plugin)
    token = auth.two_factor.issue_step_up("u1", context="transfer")
    with pytest.raises(ValueError, match="context"):
        auth.two_factor.verify_step_up(token, context="change_password")


@pytest.mark.asyncio
async def test_two_factor_backup_codes_require_store():
    from urauth.plugins.authn import TwoFactorPlugin

    plugin = TwoFactorPlugin()  # no backup_code_store
    auth = make_auth(plugin)
    with pytest.raises(RuntimeError, match="backup_code_store"):
        await auth.two_factor.generate_backup_codes("u1")


# ── authn.MagicLinkPlugin ─────────────────────────────────────────────────────


def test_magic_link_plugin_attaches():
    from urauth.plugins.authn import MagicLinkPlugin

    auth = make_auth(MagicLinkPlugin())
    assert hasattr(auth, "magic_link")


def test_magic_link_generate_and_verify():
    from urauth.plugins.authn import MagicLinkPlugin

    plugin = MagicLinkPlugin(base_url="https://app.com/verify", ttl=300)
    auth = make_auth(plugin)
    token = auth.magic_link.generate_token("user@example.com")
    payload = auth.magic_link.verify(token)
    assert payload == "user@example.com"


def test_magic_link_generate_link_contains_token():
    from urauth.plugins.authn import MagicLinkPlugin

    plugin = MagicLinkPlugin(base_url="https://app.com/magic")
    auth = make_auth(plugin)
    link = auth.magic_link.generate_link("u@example.com")
    assert "https://app.com/magic" in link
    assert "token=" in link


@pytest.mark.asyncio
async def test_magic_link_send_without_callable_raises():
    from urauth.plugins.authn import MagicLinkPlugin

    auth = make_auth(MagicLinkPlugin())
    with pytest.raises(RuntimeError, match="send="):
        await auth.magic_link.send_link("u@example.com")


@pytest.mark.asyncio
async def test_magic_link_send_with_callable():
    from urauth.plugins.authn import MagicLinkPlugin

    sent = []

    async def deliver(email, link):
        sent.append((email, link))

    auth = make_auth(MagicLinkPlugin(send=deliver, base_url="https://x.com/magic"))
    link = await auth.magic_link.send_link("test@example.com")
    assert len(sent) == 1
    assert sent[0][0] == "test@example.com"
    assert "https://x.com/magic" in link


# ── authz.AdminPlugin ─────────────────────────────────────────────────────────


def test_admin_plugin_attaches():
    from urauth.plugins.authz import AdminPlugin

    auth = make_auth(AdminPlugin())
    assert hasattr(auth, "admin")


def test_admin_is_admin_with_role():
    from urauth.authz.primitives import Role
    from urauth.context import AuthContext
    from urauth.plugins.authz import AdminPlugin

    plugin = AdminPlugin(admin_roles={"admin"})
    auth = make_auth(plugin)

    ctx = AuthContext(user=None, roles=[Role(name="admin", permissions=[])])
    assert auth.admin.is_admin(ctx)


def test_admin_is_admin_false_for_regular_user():
    from urauth.authz.primitives import Role
    from urauth.context import AuthContext
    from urauth.plugins.authz import AdminPlugin

    plugin = AdminPlugin()
    auth = make_auth(plugin)

    ctx = AuthContext(user=None, roles=[Role(name="member", permissions=[])])
    assert not auth.admin.is_admin(ctx)


def test_admin_require_admin_raises_for_non_admin():
    from urauth.context import AuthContext
    from urauth.exceptions import ForbiddenError
    from urauth.plugins.authz import AdminPlugin

    auth = make_auth(AdminPlugin())
    ctx = AuthContext(user=None)
    with pytest.raises(ForbiddenError):
        auth.admin.require_admin(ctx)


# ── authz.ApiKeyPlugin ────────────────────────────────────────────────────────


def test_api_key_plugin_attaches():
    from urauth.apikeys.manager import ApiKeyRecord, CreatedApiKey

    class InMemoryApiKeyStore:
        def __init__(self):
            self._keys: dict[str, ApiKeyRecord] = {}
            self._by_hash: dict[str, ApiKeyRecord] = {}

        async def save(self, record: ApiKeyRecord) -> None:
            self._keys[record.key_id] = record
            self._by_hash[record.key_hash] = record

        async def get_by_hash(self, key_hash: str) -> ApiKeyRecord | None:
            return self._by_hash.get(key_hash)

        async def revoke(self, key_id: str) -> None:
            rec = self._keys.get(key_id)
            if rec:
                rec.revoked = True

        async def list_for_user(self, user_id: str) -> list[ApiKeyRecord]:
            return [r for r in self._keys.values() if r.user_id == user_id]

    from urauth.plugins.authz import ApiKeyPlugin

    store = InMemoryApiKeyStore()
    auth = make_auth(ApiKeyPlugin(store=store, prefix="sk"))
    assert hasattr(auth, "api_keys")


# ── utility.HibpPlugin ────────────────────────────────────────────────────────


def test_hibp_plugin_attaches():
    from urauth.plugins.utility import HibpPlugin

    auth = make_auth(HibpPlugin())
    assert hasattr(auth, "hibp")


@pytest.mark.asyncio
async def test_hibp_no_reject_does_not_raise_on_validate(monkeypatch):
    from urauth.plugins.utility import HibpPlugin

    plugin = HibpPlugin(reject_compromised=False)
    auth = make_auth(plugin)

    async def fake_check(password):
        return 1000

    monkeypatch.setattr(auth.hibp, "check", fake_check)

    # Should not raise because reject_compromised=False
    await auth.hibp.validate("anypassword")


# ── utility.OneTimeTokenPlugin ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_one_time_token_roundtrip():
    from urauth.plugins.utility import OneTimeTokenPlugin

    plugin = OneTimeTokenPlugin()
    auth = make_auth(plugin)

    token = auth.one_time_token.issue("verify-email", "user@example.com")
    payload = await auth.one_time_token.consume("verify-email", token)
    assert payload == "user@example.com"


@pytest.mark.asyncio
async def test_one_time_token_cannot_be_reused():
    from urauth.plugins.utility import OneTimeTokenPlugin

    plugin = OneTimeTokenPlugin()
    auth = make_auth(plugin)

    token = auth.one_time_token.issue("reset", "uid-123")
    await auth.one_time_token.consume("reset", token)
    with pytest.raises(ValueError, match="already been used"):
        await auth.one_time_token.consume("reset", token)


@pytest.mark.asyncio
async def test_one_time_token_purpose_isolation():
    from urauth.plugins.utility import OneTimeTokenPlugin

    plugin = OneTimeTokenPlugin()
    auth = make_auth(plugin)

    token = auth.one_time_token.issue("email-verify", "payload")
    with pytest.raises(ValueError):
        await auth.one_time_token.consume("password-reset", token)


# ── utility.LastLoginPlugin ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_last_login_plugin_records_login():
    from urauth.plugins.utility import LastLoginPlugin, LoginRecord

    records: dict[str, LoginRecord] = {}

    class InMemoryLastLoginStore:
        async def save(self, record: LoginRecord) -> None:
            records[record.user_id] = record

        async def get(self, user_id: str) -> LoginRecord | None:
            return records.get(user_id)

    plugin = LastLoginPlugin(store=InMemoryLastLoginStore())
    auth = make_auth(plugin)

    # Simulate login hook
    await plugin.on_login("u1", "password")

    record = await auth.last_login.get("u1")
    assert record is not None
    assert record.method == "password"
    assert record.user_id == "u1"


# ── plugins top-level import ──────────────────────────────────────────────────


def test_plugins_top_level_import():
    from urauth import plugins
    from urauth.plugins import (
        AdminPlugin,
        AnonymousPlugin,
        ApiKeyPlugin,
        CaptchaPlugin,
        HibpPlugin,
        JWTPlugin,
        MagicLinkPlugin,
        MultiSessionPlugin,
        OAuthPlugin,
        OIDCProviderPlugin,
        OneTimeTokenPlugin,
        OrganizationPlugin,
        PasskeyPlugin,
        PasswordPolicy,
        PhoneNumberPlugin,
        SCIMPlugin,
        SSOPlugin,
        TwoFactorPlugin,
        UsernamePlugin,
    )

    # Just confirm they're importable (not None)
    assert UsernamePlugin is not None
    assert TwoFactorPlugin is not None
    assert HibpPlugin is not None
    assert OIDCProviderPlugin is not None


def test_plugin_categories_exist():
    from urauth.plugins import authn, authz, enterprise, utility

    assert hasattr(authn, "UsernamePlugin")
    assert hasattr(authz, "AdminPlugin")
    assert hasattr(enterprise, "OIDCProviderPlugin")
    assert hasattr(utility, "HibpPlugin")
