"""Tests for pipeline configuration models."""

from __future__ import annotations

from urauth.pipeline import (
    AccountLinking,
    APIKeyStrategy,
    BasicAuthStrategy,
    Discord,
    FallbackStrategy,
    GitHub,
    Google,
    Identifiers,
    JWTStrategy,
    MagicLinkLogin,
    MFAMethod,
    Microsoft,
    OAuthLogin,
    OTPLogin,
    PasskeyLogin,
    PasswordLogin,
    PasswordReset,
    Pipeline,
    SessionStrategy,
)


class TestStrategies:
    def test_jwt_defaults(self):
        s = JWTStrategy()
        assert s.kind == "jwt"
        assert s.refresh is True
        assert s.revocable is True
        assert s.transport == "bearer"

    def test_jwt_custom(self):
        s = JWTStrategy(refresh=False, revocable=False, transport="cookie")
        assert s.refresh is False
        assert s.revocable is False
        assert s.transport == "cookie"

    def test_session_defaults(self):
        s = SessionStrategy()
        assert s.kind == "session"
        assert s.cookie_name == "session_id"

    def test_basic_auth(self):
        s = BasicAuthStrategy()
        assert s.kind == "basic"
        assert s.realm == "Restricted"

    def test_api_key(self):
        s = APIKeyStrategy(header_name="X-Custom-Key", query_param="key")
        assert s.header_name == "X-Custom-Key"
        assert s.query_param == "key"

    def test_fallback(self):
        s = FallbackStrategy(strategies=[JWTStrategy(), APIKeyStrategy()])
        assert len(s.strategies) == 2
        assert isinstance(s.strategies[0], JWTStrategy)
        assert isinstance(s.strategies[1], APIKeyStrategy)


class TestOAuthProviders:
    def test_google(self):
        p = Google(client_id="id", client_secret="secret")
        assert p.name == "google"
        assert p.client_id == "id"

    def test_github(self):
        p = GitHub(client_id="id", client_secret="secret", scopes=["user:email"])
        assert p.name == "github"
        assert p.scopes == ["user:email"]

    def test_microsoft(self):
        p = Microsoft(client_id="id", client_secret="secret")
        assert p.name == "microsoft"

    def test_discord(self):
        p = Discord(client_id="id", client_secret="secret")
        assert p.name == "discord"


class TestLoginMethods:
    def test_password_login(self):
        m = PasswordLogin()
        assert m.kind == "password"
        assert m.enabled is True

    def test_oauth_login(self):
        m = OAuthLogin(providers=[Google(client_id="id", client_secret="s")])
        assert m.kind == "oauth"
        assert len(m.providers) == 1

    def test_magic_link(self):
        m = MagicLinkLogin(token_ttl=300)
        assert m.token_ttl == 300

    def test_otp_numeric(self):
        m = OTPLogin(code_type="numeric", digits=8)
        assert m.code_type == "numeric"
        assert m.digits == 8

    def test_otp_alpha(self):
        m = OTPLogin(code_type="alpha")
        assert m.code_type == "alpha"

    def test_otp_alphanumeric(self):
        m = OTPLogin(code_type="alphanumeric")
        assert m.code_type == "alphanumeric"

    def test_passkey(self):
        m = PasskeyLogin(rp_name="TestApp")
        assert m.kind == "passkey"
        assert m.rp_name == "TestApp"


class TestMFAMethod:
    def test_defaults(self):
        m = MFAMethod(method="otp")
        assert m.method == "otp"
        assert m.required is False
        assert m.grace_period == 0

    def test_custom(self):
        m = MFAMethod(method="passkey", required=True, grace_period=300)
        assert m.method == "passkey"
        assert m.required is True
        assert m.grace_period == 300

    def test_list_config(self):
        mfa = [MFAMethod(method="otp", required=False), MFAMethod(method="passkey")]
        assert len(mfa) == 2
        assert mfa[0].method == "otp"
        assert mfa[1].method == "passkey"


class TestAccountFeatures:
    def test_password_reset_defaults(self):
        p = PasswordReset()
        assert p.token_ttl == 3600
        assert p.reset_session_ttl == 600

    def test_password_reset_custom(self):
        p = PasswordReset(token_ttl=1800, reset_session_ttl=300)
        assert p.token_ttl == 1800

    def test_account_linking(self):
        a = AccountLinking()
        assert a is not None

    def test_identifiers(self):
        i = Identifiers(email=True, phone=True, username=False)
        assert i.email is True
        assert i.phone is True
        assert i.username is False


class TestPipeline:
    def test_defaults(self):
        p = Pipeline()
        assert isinstance(p.strategy, JWTStrategy)
        assert p.password is False
        assert p.oauth is None
        assert p.mfa is None
        assert p.has_password_reset is False
        assert p.has_account_linking is False
        assert p.has_mfa is False

    def test_enabled_methods_empty(self):
        p = Pipeline()
        assert p.enabled_methods() == []

    def test_enabled_methods_password_bool(self):
        p = Pipeline(password=True)
        methods = p.enabled_methods()
        assert len(methods) == 1
        assert isinstance(methods[0], PasswordLogin)

    def test_enabled_methods_password_model(self):
        p = Pipeline(password=PasswordLogin(enabled=True))
        methods = p.enabled_methods()
        assert len(methods) == 1

    def test_enabled_methods_password_disabled(self):
        p = Pipeline(password=PasswordLogin(enabled=False))
        methods = p.enabled_methods()
        assert len(methods) == 0

    def test_enabled_methods_oauth(self):
        p = Pipeline(oauth=OAuthLogin(providers=[Google(client_id="id", client_secret="s")]))
        methods = p.enabled_methods()
        assert len(methods) == 1
        assert isinstance(methods[0], OAuthLogin)

    def test_enabled_methods_passkey_bool(self):
        p = Pipeline(passkey=True)
        methods = p.enabled_methods()
        assert len(methods) == 1
        assert isinstance(methods[0], PasskeyLogin)

    def test_enabled_methods_all(self):
        p = Pipeline(
            password=True,
            oauth=OAuthLogin(providers=[Google(client_id="id", client_secret="s")]),
            magic_link=MagicLinkLogin(),
            otp=OTPLogin(),
            passkey=True,
        )
        methods = p.enabled_methods()
        assert len(methods) == 5

    def test_has_password_reset_bool(self):
        p = Pipeline(password_reset=True)
        assert p.has_password_reset is True
        assert isinstance(p.password_reset_config, PasswordReset)

    def test_has_password_reset_model(self):
        p = Pipeline(password_reset=PasswordReset(token_ttl=1800))
        assert p.has_password_reset is True
        assert p.password_reset_config.token_ttl == 1800

    def test_has_account_linking(self):
        p = Pipeline(account_linking=True)
        assert p.has_account_linking is True

    def test_has_mfa(self):
        p = Pipeline(mfa=[MFAMethod(method="otp")])
        assert p.has_mfa is True

    def test_has_mfa_empty_list(self):
        p = Pipeline(mfa=[])
        assert p.has_mfa is False

    def test_full_pipeline(self):
        """Test a fully-configured pipeline like the example in the docstring."""
        p = Pipeline(
            strategy=JWTStrategy(refresh=True, revocable=True),
            password=True,
            oauth=OAuthLogin(
                providers=[
                    Google(client_id="gid", client_secret="gsecret"),
                    GitHub(client_id="ghid", client_secret="ghsecret"),
                ]
            ),
            magic_link=MagicLinkLogin(),
            otp=OTPLogin(code_type="numeric", digits=6),
            passkey=True,
            mfa=[MFAMethod(method="otp"), MFAMethod(method="passkey")],
            password_reset=True,
            account_linking=True,
            identifiers=Identifiers(email=True, phone=True, username=False),
        )

        assert isinstance(p.strategy, JWTStrategy)
        assert len(p.enabled_methods()) == 5
        assert p.has_mfa is True
        assert p.has_password_reset is True
        assert p.has_account_linking is True
        assert p.identifiers.phone is True
