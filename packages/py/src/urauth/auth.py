"""Framework-agnostic Auth base class.

All overridable hook methods accept both sync and async implementations::

    class MyAuth(Auth):
        def send_reset_email(self, email, token, link):   # sync — works
            mailer.send(email, token, link)

    class AsyncAuth(Auth):
        async def send_reset_email(self, email, token, link):  # async — also works
            await mailer.send(email, token, link)
"""

from __future__ import annotations

import warnings
from typing import Any, Literal

from urauth._async import maybe_await, run_sync
from urauth.authz.primitives import Permission, Relation
from urauth.storage.base import SessionStore, TokenStore
from urauth.storage.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.audit.events import AuthEventHandler
from urauth.exceptions import UnauthorizedError
from urauth.plugin import PluginRegistry, UrAuthPlugin
from urauth.methods import (
    JWT,
    MFA,
    OTP,
    TOTP,
    AccountLinking,
    Email,
    Fallback,
    Identifiers,
    Identity,
    MagicLink,
    Method,
    OAuth,
    Passkey,
    Password,
    Phone,
    ResetablePassword,
    Session,
    Username,
)
from urauth.results import AuthResult, LoginResult, MessageResult, MFARequiredResult, ResetSessionResult
from urauth.tenant.hierarchy import TenantPath
from urauth.tokens.lifecycle import IssuedTokenPair, IssueRequest, TokenLifecycle
from urauth.types import TokenPayload
from urauth.users import UserDataMixin

SameSitePolicy = Literal["lax", "strict", "none"]

_HMAC_ALGORITHMS = {"HS256", "HS384", "HS512"}
_MIN_HMAC_KEY_LENGTH = 32
_WEAK_SECRETS = frozenset(
    {
        "secret",
        "password",
        "changeme",
        "change-me",
        "test",
        "key",
        "mysecret",
        "jwt-secret",
    }
)

# Names of all user-data hook methods on UserDataMixin.
_USER_HOOK_NAMES: tuple[str, ...] = (
    "get_user",
    "get_user_by_username",
    "verify_password",
    "get_user_roles",
    "get_user_permissions",
    "get_user_relations",
    "check_relation",
    "get_user_by_identifier",
    "get_user_by_email",
    "get_user_by_phone",
    "get_user_by_api_key",
    "get_or_create_oauth_user",
)


class Auth(UserDataMixin):
    """Framework-agnostic auth class.

    Two patterns for wiring user data access:

    **Subclass** (recommended for larger apps)::

        class MyAuth(Auth):
            async def get_user(self, user_id): ...
            async def get_user_by_username(self, username): ...
            async def verify_password(self, user, password): ...

        auth = MyAuth(method=JWT(...), secret_key="...")

    **Mixin composition** (with contrib stores)::

        class MyAuth(Auth, SQLAlchemyUserStore):
            pass

        auth = MyAuth(session_factory=sf, user_model=User, method=JWT(...), secret_key="...")

    **Callable kwargs** (quick & declarative)::

        auth = Auth(
            get_user=lambda uid: USERS_DB.get(str(uid)),
            get_user_by_username=lambda u: ...,
            verify_password=lambda user, pw: ...,
            method=JWT(...), secret_key="...",
        )

    All three patterns support both sync and async implementations.
    The ``method`` parameter defines how authenticated state is maintained
    per-request (JWT, Session, BasicAuth, APIKey, or Fallback).
    Login methods (password, oauth, magic_link, otp, passkey) define
    how users initially prove their identity.
    """

    # ── Strategy hooks (non-data operations) ────────────────────

    def send_magic_link(self, email: str, token: str, link: str) -> None:
        raise NotImplementedError("Override send_magic_link() to use magic link login")

    def verify_magic_link_token(self, token: str) -> Any | None:
        raise NotImplementedError("Override verify_magic_link_token() to use magic link login")

    # ── Password reset hooks (3-step flow) ──────────────────────

    def create_reset_token(self, user: Any) -> str:
        raise NotImplementedError("Override create_reset_token() to use password reset")

    def send_reset_email(self, email: str, token: str, link: str) -> None:
        raise NotImplementedError("Override send_reset_email() to use password reset")

    def validate_reset_token(self, token: str) -> Any | None:
        raise NotImplementedError("Override validate_reset_token() to use password reset")

    def invalidate_password(self, user: Any) -> None:
        raise NotImplementedError("Override invalidate_password() to use password reset")

    def set_password(self, user: Any, new_password: str) -> None:
        raise NotImplementedError("Override set_password() to use password reset")

    # ── Account linking hooks ───────────────────────────────────

    def link_oauth(self, user: Any, info: Any) -> None:
        raise NotImplementedError("Override link_oauth() to use account linking")

    def unlink_oauth(self, user: Any, provider: str) -> None:
        raise NotImplementedError("Override unlink_oauth() to use account linking")

    def link_phone(self, user: Any, phone: str) -> None:
        raise NotImplementedError("Override link_phone() to use account linking")

    def link_email(self, user: Any, email: str) -> None:
        raise NotImplementedError("Override link_email() to use account linking")

    def get_linked_accounts(self, user: Any) -> list[dict[str, Any]]:
        raise NotImplementedError("Override get_linked_accounts() to use account linking")

    # ── Passkey / WebAuthn hooks ────────────────────────────────

    def create_passkey_challenge(self, user: Any | None = None) -> dict[str, Any]:
        raise NotImplementedError("Override create_passkey_challenge() to use passkeys")

    def verify_passkey_registration(self, user: Any, credential: dict[str, Any]) -> None:
        raise NotImplementedError("Override verify_passkey_registration() to use passkeys")

    def verify_passkey_assertion(self, challenge: dict[str, Any], credential: dict[str, Any]) -> Any | None:
        raise NotImplementedError("Override verify_passkey_assertion() to use passkeys")

    def get_user_passkeys(self, user: Any) -> list[dict[str, Any]]:
        raise NotImplementedError("Override get_user_passkeys() to use passkeys")

    def delete_passkey(self, user: Any, credential_id: str) -> None:
        raise NotImplementedError("Override delete_passkey() to use passkeys")

    # ── MFA hooks ───────────────────────────────────────────────

    def is_mfa_enrolled(self, user: Any) -> bool:
        return False

    def get_mfa_methods(self, user: Any) -> list[str]:
        return []

    def enroll_mfa(self, user: Any, method: str) -> dict[str, Any]:
        raise NotImplementedError("Override enroll_mfa() to use MFA")

    def verify_mfa(self, user: Any, method: str, code: str) -> bool:
        raise NotImplementedError("Override verify_mfa() to use MFA")

    # ── Tenant hierarchy hooks ──────────────────────────────────

    def resolve_tenant_path(self, user: Any, payload: TokenPayload | None) -> TenantPath | None:
        """Resolve the tenant hierarchy path for the current context.

        Default reads ``tenant_path`` from the token claim, falling back
        to wrapping ``tenant_id`` in a single-node path. Override to
        resolve hierarchy from your database.
        """
        if payload and payload.tenant_path:
            return TenantPath.from_claim(payload.tenant_path)
        if payload and payload.tenant_id:
            return TenantPath.from_flat(payload.tenant_id)
        tenant_id = getattr(user, "tenant_id", None) if user else None
        if tenant_id:
            return TenantPath.from_flat(str(tenant_id))
        return None

    def get_tenant_permissions(self, user: Any, level: str, tenant_id: str) -> list[Permission]:
        """Return permissions scoped to a specific tenant level.

        Override to load tenant-scoped permissions from your database.
        """
        return []

    # ── Constructor ─────────────────────────────────────────────

    def __init__(
        self,
        *,
        # Auth method (includes TTLs, stores)
        method: Method | None = None,

        # Security
        secret_key: str = "CHANGE-ME-IN-PRODUCTION",
        algorithm: str = "HS256",
        environment: Literal["development", "production", "testing"] = "development",
        allow_insecure_key: bool = False,
        password_hash_scheme: str = "bcrypt",

        # Cookie settings (for cookie/hybrid transport)
        cookie_name: str = "access_token",
        cookie_secure: bool = True,
        cookie_httponly: bool = True,
        cookie_samesite: SameSitePolicy = "lax",
        cookie_max_age: int | None = None,
        cookie_domain: str | None = None,
        cookie_path: str = "/",

        # CSRF
        csrf_enabled: bool = False,
        csrf_cookie_name: str = "csrf_token",
        csrf_header_name: str = "X-CSRF-Token",

        # Tenant
        tenant_enabled: bool = False,
        tenant_header: str = "X-Tenant-ID",
        tenant_claim: str = "tenant_id",
        tenant_hierarchy_enabled: bool = False,
        tenant_hierarchy_levels: list[str] | None = None,
        tenant_path_claim: str = "tenant_path",
        tenant_default_level: str = "tenant",

        # Router
        auth_prefix: str = "/auth",

        # Identity — what users log in with
        identity: Identity | list[Identity] | None = None,

        # Login methods
        password: Password | ResetablePassword | None = None,
        oauth: OAuth | None = None,
        magic_link: MagicLink | None = None,
        otp: OTP | None = None,
        totp: TOTP | None = None,
        passkey: Passkey | None = None,

        # Features
        mfa: MFA | None = None,
        account_linking: AccountLinking | None = None,
        identifiers: Identifiers = Identifiers(),

        # Events
        event_handler: AuthEventHandler | None = None,

        # Plugins
        plugins: list[UrAuthPlugin] | None = None,

        # Multi-project
        namespace: str | None = None,

        # User-data hook callables — passed instead of (or alongside) subclassing.
        # Subclass overrides take priority: a callable is only installed if the
        # corresponding method has not been overridden anywhere in the MRO.
        get_user: Any | None = None,
        get_user_by_username: Any | None = None,
        verify_password: Any | None = None,
        get_user_roles: Any | None = None,
        get_user_permissions: Any | None = None,
        get_user_relations: Any | None = None,
        check_relation: Any | None = None,
        get_user_by_identifier: Any | None = None,
        get_user_by_email: Any | None = None,
        get_user_by_phone: Any | None = None,
        get_user_by_api_key: Any | None = None,
        get_or_create_oauth_user: Any | None = None,

        # Backward compat — old API accepted these
        config: Any | None = None,
        token_store: TokenStore | None = None,
        session_store: SessionStore | None = None,
        pipeline: Any | None = None,

        # Cooperative multiple-inheritance kwargs pass-through (e.g. for
        # class MyAuth(Auth, SQLAlchemyUserStore) — mixin __init__ pops its own keys)
        **extra_kwargs: Any,
    ) -> None:
        # Handle backward compat: if config= passed, extract its fields
        if config is not None:
            if isinstance(config, AuthConfig):
                secret_key = config.secret_key
                algorithm = config.algorithm
                environment = config.environment
                allow_insecure_key = config.allow_insecure_key
                password_hash_scheme = config.password_hash_scheme
                cookie_name = config.cookie_name
                cookie_secure = config.cookie_secure
                cookie_httponly = config.cookie_httponly
                cookie_samesite = config.cookie_samesite
                cookie_max_age = config.cookie_max_age
                cookie_domain = config.cookie_domain
                cookie_path = config.cookie_path
                csrf_enabled = config.csrf_enabled
                csrf_cookie_name = config.csrf_cookie_name
                csrf_header_name = config.csrf_header_name
                tenant_enabled = config.tenant_enabled
                tenant_header = config.tenant_header
                tenant_claim = config.tenant_claim
                tenant_hierarchy_enabled = config.tenant_hierarchy_enabled
                tenant_hierarchy_levels = config.tenant_hierarchy_levels
                tenant_path_claim = config.tenant_path_claim
                tenant_default_level = config.tenant_default_level
                auth_prefix = config.auth_prefix

        # Handle backward compat: if token_store passed directly, wrap in JWT method
        if method is None:
            if token_store is not None:
                method = JWT(store=token_store)
                if config is not None:
                    method = JWT(
                        store=token_store,
                        ttl=config.access_token_ttl,
                        refresh_ttl=config.refresh_token_ttl,
                        issuer=config.token_issuer,
                        audience=config.token_audience,
                    )
            else:
                method = JWT()

        # Install callable kwargs as instance attributes (subclass overrides take priority).
        self._install_user_hooks({
            "get_user": get_user,
            "get_user_by_username": get_user_by_username,
            "verify_password": verify_password,
            "get_user_roles": get_user_roles,
            "get_user_permissions": get_user_permissions,
            "get_user_relations": get_user_relations,
            "check_relation": check_relation,
            "get_user_by_identifier": get_user_by_identifier,
            "get_user_by_email": get_user_by_email,
            "get_user_by_phone": get_user_by_phone,
            "get_user_by_api_key": get_user_by_api_key,
            "get_or_create_oauth_user": get_or_create_oauth_user,
        })
        self.namespace = namespace

        # Auth method
        self.method = method

        # Store config fields for internal use
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.environment: Literal["development", "production", "testing"] = environment  # type: ignore[assignment]
        self.allow_insecure_key = allow_insecure_key
        self.password_hash_scheme = password_hash_scheme
        self.cookie_name = cookie_name
        self.cookie_secure = cookie_secure
        self.cookie_httponly = cookie_httponly
        self.cookie_samesite: SameSitePolicy = cookie_samesite  # type: ignore[assignment]
        self.cookie_max_age = cookie_max_age
        self.cookie_domain = cookie_domain
        self.cookie_path = cookie_path
        self.csrf_enabled = csrf_enabled
        self.csrf_cookie_name = csrf_cookie_name
        self.csrf_header_name = csrf_header_name
        self.tenant_enabled = tenant_enabled
        self.tenant_header = tenant_header
        self.tenant_claim = tenant_claim
        self.tenant_hierarchy_enabled = tenant_hierarchy_enabled
        self.tenant_hierarchy_levels = tenant_hierarchy_levels
        self.tenant_path_claim = tenant_path_claim
        self.tenant_default_level = tenant_default_level
        self.auth_prefix = auth_prefix

        # Login methods
        self.password = password
        self.oauth = oauth
        self.magic_link = magic_link
        self.otp = otp
        self.totp = totp
        self.passkey = passkey

        # Features
        self.mfa = mfa
        self.account_linking = account_linking
        self.identifiers = identifiers

        # Resolve identity list
        self.identity: list[Identity] = self._resolve_identity(identity)

        # Validate secret key
        self._validate_secret_key()

        # Build internal AuthConfig for TokenLifecycle / TokenService
        config = self._build_internal_config()

        # Resolve token store from method
        token_store = self._resolve_token_store()
        self.token_store = token_store

        # Resolve session store from method (or backward compat direct arg)
        self.session_store = session_store or self._resolve_session_store()

        # Internal config object (used by TokenLifecycle, transports, middleware)
        self.internal_config = config

        # Build lifecycle
        self.lifecycle = TokenLifecycle(config, token_store, event_handler=event_handler, namespace=namespace)
        self.token_service = self.lifecycle.jwt  # backward compat

        # Forward remaining kwargs to the next class in the MRO (e.g. contrib mixins).
        super().__init__(**extra_kwargs)

        # Plugin registry — setup_all() runs after super().__init__ so that
        # contrib mixins (SQLAlchemy, SQLModel) are fully initialised before
        # plugins receive the Auth instance.
        self.plugins: PluginRegistry = PluginRegistry(list(plugins or []))
        self.plugins.setup_all(self)

    def _install_user_hooks(self, hooks: dict[str, Any]) -> None:
        """Install callable kwargs as instance attributes.

        Only installs a callable if the corresponding method has not been
        overridden anywhere in the MRO (subclass wins over callable kwarg).
        """
        for name, fn in hooks.items():
            if fn is None:
                continue
            if getattr(type(self), name) is not getattr(UserDataMixin, name):
                # A subclass (or contrib mixin) has overridden this method — skip.
                continue
            setattr(self, name, fn)

    def _validate_secret_key(self) -> None:
        """Validate secret key security based on environment."""
        # In testing mode, default to allowing insecure keys
        if self.environment == "testing" and not self.allow_insecure_key:
            self.allow_insecure_key = True

        # In production mode, never allow insecure keys
        if self.environment == "production" and self.allow_insecure_key:
            raise ValueError(
                "urauth: allow_insecure_key=True is not permitted in production environment. "
                "Set environment to 'development' or 'testing' to use insecure keys."
            )

        if self.allow_insecure_key:
            if self.secret_key == "CHANGE-ME-IN-PRODUCTION":
                warnings.warn(
                    "urauth: Using default secret key 'CHANGE-ME-IN-PRODUCTION'. "
                    "Set a secure secret_key for production use.",
                    UserWarning,
                    stacklevel=3,
                )
            return

        if self.secret_key == "CHANGE-ME-IN-PRODUCTION":
            raise ValueError(
                "urauth: Default secret key 'CHANGE-ME-IN-PRODUCTION' is not allowed. "
                "Pass a secure secret_key. "
                "For development/testing, set allow_insecure_key=True."
            )

        key = self.secret_key.strip()
        if not key:
            raise ValueError("urauth: secret_key must not be empty or whitespace-only.")

        if key.lower() in _WEAK_SECRETS:
            raise ValueError(
                f"urauth: secret_key '{key}' is a commonly used weak secret. "
                "Use a random key of at least 32 bytes (e.g. `openssl rand -hex 32`)."
            )

        if self.algorithm in _HMAC_ALGORITHMS and len(self.secret_key) < _MIN_HMAC_KEY_LENGTH:
            raise ValueError(
                f"urauth: secret_key must be at least {_MIN_HMAC_KEY_LENGTH} characters "
                f"for HMAC algorithm {self.algorithm}. "
                "Use `openssl rand -hex 32` to generate a secure key."
            )

    def _build_internal_config(self) -> AuthConfig:
        """Build an internal AuthConfig-like object for TokenLifecycle."""
        # Extract TTLs from method config
        access_ttl = 900
        refresh_ttl = 604800
        token_issuer = None
        token_audience = None

        if isinstance(self.method, JWT):
            access_ttl = self.method.ttl
            refresh_ttl = self.method.refresh_ttl
            token_issuer = self.method.issuer
            token_audience = self.method.audience
        elif isinstance(self.method, Fallback):
            # Use the first JWT method's TTLs if available
            for m in self.method.methods:
                if isinstance(m, JWT):
                    access_ttl = m.ttl
                    refresh_ttl = m.refresh_ttl
                    token_issuer = m.issuer
                    token_audience = m.audience
                    break

        return AuthConfig(
            secret_key=self.secret_key,
            algorithm=self.algorithm,
            access_token_ttl=access_ttl,
            refresh_token_ttl=refresh_ttl,
            token_issuer=token_issuer,
            token_audience=token_audience,
            environment=self.environment,
            allow_insecure_key=self.allow_insecure_key,
            password_hash_scheme=self.password_hash_scheme,
            cookie_name=self.cookie_name,
            cookie_secure=self.cookie_secure,
            cookie_httponly=self.cookie_httponly,
            cookie_samesite=self.cookie_samesite,
            cookie_max_age=self.cookie_max_age,
            cookie_domain=self.cookie_domain,
            cookie_path=self.cookie_path,
            csrf_enabled=self.csrf_enabled,
            csrf_cookie_name=self.csrf_cookie_name,
            csrf_header_name=self.csrf_header_name,
            tenant_enabled=self.tenant_enabled,
            tenant_header=self.tenant_header,
            tenant_claim=self.tenant_claim,
            tenant_hierarchy_enabled=self.tenant_hierarchy_enabled,
            tenant_hierarchy_levels=self.tenant_hierarchy_levels,
            tenant_path_claim=self.tenant_path_claim,
            tenant_default_level=self.tenant_default_level,
            auth_prefix=self.auth_prefix,
        )

    def _resolve_token_store(self) -> TokenStore:
        """Resolve token store from method config."""
        if isinstance(self.method, JWT):
            return self.method.store or MemoryTokenStore()
        if isinstance(self.method, Fallback):
            for m in self.method.methods:
                if isinstance(m, JWT) and m.store is not None:
                    return m.store
        return MemoryTokenStore()

    def _resolve_session_store(self) -> SessionStore | None:
        """Resolve session store from method config."""
        if isinstance(self.method, Session):
            return self.method.store
        if isinstance(self.method, Fallback):
            for m in self.method.methods:
                if isinstance(m, Session) and m.store is not None:
                    return m.store
        return None

    def _resolve_identity(self, identity_arg: Identity | list[Identity] | None) -> list[Identity]:
        """Resolve the identity list from explicit arg or backward-compat params."""
        if identity_arg is not None:
            if isinstance(identity_arg, list):
                return identity_arg
            return [identity_arg]

        # Build from old-style params (identifiers, otp, magic_link)
        # In backward-compat mode, always include Username so the login
        # schema uses a generic 'identifier' field (matching old behavior)
        result: list[Identity] = [Username()]
        if self.identifiers.email:
            result.append(Email(otp=self.otp, magic_link=self.magic_link))
        if self.identifiers.phone:
            result.append(Phone(otp=self.otp))
        return result

    # ── Identity analysis properties ────────────────────────────

    @property
    def otp_channels(self) -> list[Email | Phone]:
        """Delivery channels (Email/Phone) with OTP configured."""
        return [
            i for i in self.identity
            if isinstance(i, (Email, Phone)) and i.otp is not None
        ]

    @property
    def has_password_reset(self) -> bool:
        """Whether password reset is available (password + at least one OTP channel)."""
        return self.password is not None and len(self.otp_channels) > 0

    @property
    def magic_link_email(self) -> Email | None:
        """The Email identity with magic_link configured, if any."""
        for i in self.identity:
            if isinstance(i, Email) and i.magic_link is not None:
                return i
        return None

    def _find_otp_for_channel(self, channel: str | None = None) -> OTP | None:
        """Find an OTP config from the identity list, optionally by channel name."""
        channels = self.otp_channels
        if not channels:
            return self.otp  # backward compat: fall back to top-level otp=
        if channel == "email":
            return next((c.otp for c in channels if isinstance(c, Email)), None)
        if channel == "phone":
            return next((c.otp for c in channels if isinstance(c, Phone)), None)
        # Default to first available channel
        return channels[0].otp

    # ── Async context building ──────────────────────────────────

    async def build_context(
        self,
        raw_token: str | None,
        *,
        optional: bool = False,
        request: Any = None,
    ) -> AuthContext:
        """Build AuthContext from a raw JWT token string."""
        if raw_token is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError()

        try:
            payload: TokenPayload = await self.lifecycle.validate(raw_token)
        except Exception:
            if optional:
                return AuthContext.anonymous(request=request)
            raise

        # Check namespace
        if self.namespace is not None:
            token_ns = payload.extra.get("ns")
            if token_ns != self.namespace:
                if optional:
                    return AuthContext.anonymous(request=request)
                raise UnauthorizedError("Token namespace mismatch")

        # Load user
        user = await maybe_await(self.get_user(payload.sub))
        if user is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError("User not found")

        if not getattr(user, "is_active", True):
            raise UnauthorizedError("Inactive user")

        return await self.build_user_context(user, payload=payload, request=request)

    async def build_context_for_user(
        self,
        user: Any,
        *,
        request: Any = None,
    ) -> AuthContext:
        """Build AuthContext from a user object."""
        return await self.build_user_context(user, request=request)

    async def build_user_context(
        self,
        user: Any,
        *,
        payload: TokenPayload | None = None,
        request: Any = None,
    ) -> AuthContext:
        """Load roles/permissions/relations and assemble context."""
        roles = await maybe_await(self.get_user_roles(user))
        direct_permissions = await maybe_await(self.get_user_permissions(user))
        relations = await maybe_await(self.get_user_relations(user))

        all_permissions: list[Permission] = list(direct_permissions)
        for role in roles:
            all_permissions.extend(role.permissions)

        # Resolve tenant hierarchy
        tenant_path = await maybe_await(self.resolve_tenant_path(user, payload))

        # Build scoped permissions from tenant hierarchy (cascading inheritance)
        scopes: dict[str, list[Permission]] = {}
        if tenant_path is not None:
            for node in tenant_path:
                level_perms = await maybe_await(
                    self.get_tenant_permissions(user, node.level, node.id)
                )
                if level_perms:
                    scopes[node.level] = level_perms

        ctx = AuthContext(
            user=user,
            roles=roles,
            permissions=all_permissions,
            relations=relations,
            scopes=scopes,
            token=payload,
            request=request,
            tenant=tenant_path,
        )
        await self.plugins.emit("on_context_built", context=ctx)
        return ctx

    # ── Endpoint methods (framework-agnostic) ───────────────────

    async def _resolve_user(self, identifier: str) -> Any | None:
        """Try each configured identity type to resolve a user."""
        for ident in self.identity:
            user = None
            if isinstance(ident, Username):
                user = await maybe_await(self.get_user_by_username(identifier))
            elif isinstance(ident, Email):
                user = await maybe_await(self.get_user_by_email(identifier))
            elif isinstance(ident, Phone):
                user = await maybe_await(self.get_user_by_phone(identifier))
            if user is not None:
                return user
        return None

    async def login(self, identifier: str, password: str) -> LoginResult:
        """Authenticate with identifier + password. Returns tokens or MFA challenge."""
        user = await self._resolve_user(identifier)
        if user is None:
            await self.plugins.emit("on_login_failed", identifier=identifier)
            raise UnauthorizedError("Invalid credentials")

        if not getattr(user, "is_active", True):
            await self.plugins.emit("on_login_failed", identifier=identifier)
            raise UnauthorizedError("Inactive user")

        valid = await maybe_await(self.verify_password(user, password))
        if not valid:
            await self.plugins.emit("on_login_failed", identifier=identifier)
            raise UnauthorizedError("Invalid credentials")

        result = await self.issue_for_user(user)
        await self.plugins.emit("on_login", user_id=str(getattr(user, "id", identifier)), method="password")
        return result

    async def refresh_tokens(self, refresh_token: str) -> AuthResult:
        """Rotate a refresh token and return new token pair."""
        # Decode user_id before refresh (validation happens inside lifecycle.refresh)
        try:
            _claims = self.token_service.decode_token(refresh_token)
            _refresh_user_id = _claims.get("sub", "")
        except Exception:
            _refresh_user_id = ""
        pair = await self.lifecycle.refresh(refresh_token)
        await self.plugins.emit("on_token_refresh", user_id=_refresh_user_id)
        return AuthResult(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            family_id=pair.family_id,
        )

    async def logout(self, raw_token: str) -> None:
        """Revoke the session (family) associated with a token."""
        try:
            claims = self.token_service.decode_token(raw_token)
            user_id = claims.get("sub", "")
        except Exception:
            user_id = ""
        await self.lifecycle.revoke(raw_token)
        await self.plugins.emit("on_logout", user_id=user_id)

    async def logout_all(self, raw_token: str) -> None:
        """Revoke ALL tokens for the user who owns this token."""
        try:
            claims = self.token_service.decode_token(raw_token)
        except Exception:
            return
        await self.lifecycle.revoke_all(claims["sub"])
        await self.plugins.emit("on_logout", user_id=claims["sub"])

    async def send_otp_code(
        self, identifier: str, *, otp_instance: OTP | None = None, channel: str | None = None
    ) -> MessageResult:
        """Send an OTP code to a user.

        Resolution order: explicit ``otp_instance`` > ``channel`` lookup > first OTP channel > top-level ``otp=``.
        """
        otp_cfg = otp_instance or self._find_otp_for_channel(channel)
        if otp_cfg is None:
            raise NotImplementedError("No OTP configuration found in identity list or top-level otp=")

        user = await self._resolve_user(identifier)
        if user is None:
            # Don't reveal whether user exists
            return MessageResult(detail="If the account exists, a code has been sent.")

        import secrets
        if otp_cfg.code_type == "numeric":
            code = "".join(secrets.choice("0123456789") for _ in range(otp_cfg.digits))
        elif otp_cfg.code_type == "alpha":
            code = "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(otp_cfg.digits))
        else:
            code = "".join(
                secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(otp_cfg.digits)
            )

        await maybe_await(otp_cfg.send(user, code))
        return MessageResult(detail="If the account exists, a code has been sent.")

    async def verify_otp_login(self, identifier: str, code: str, *, channel: str | None = None) -> LoginResult:
        """Verify an OTP code and issue tokens."""
        otp_cfg = self._find_otp_for_channel(channel)
        if otp_cfg is None:
            raise NotImplementedError("No OTP configuration found")

        user = await self._resolve_user(identifier)
        if user is None:
            raise UnauthorizedError("Invalid credentials")

        valid = await maybe_await(otp_cfg.verify(user, code))
        if not valid:
            await self.plugins.emit("on_login_failed", identifier=identifier)
            raise UnauthorizedError("Invalid OTP code")

        result = await self.issue_for_user(user)
        await self.plugins.emit("on_login", user_id=str(getattr(user, "id", identifier)), method="otp")
        return result

    async def send_magic_link_request(self, email: str) -> MessageResult:
        """Send a magic link to an email address."""
        user = await maybe_await(self.get_user_by_identifier(email))
        if user is None:
            return MessageResult(detail="If the account exists, a magic link has been sent.")

        token = self.token_service.create_access_token(
            str(user.id), _internal_type="magic_link"
        )
        link = f"/auth/magic-link/verify?token={token}"
        await maybe_await(self.send_magic_link(email, token, link))
        return MessageResult(detail="If the account exists, a magic link has been sent.")

    async def verify_magic_link(self, token: str) -> LoginResult:
        """Verify a magic link token and issue credentials."""
        user = await maybe_await(self.verify_magic_link_token(token))
        if user is None:
            raise UnauthorizedError("Invalid or expired magic link")
        result = await self.issue_for_user(user)
        await self.plugins.emit("on_login", user_id=str(getattr(user, "id", "")), method="magic_link")
        return result

    async def forgot_password(self, identifier: str, *, channel: str | None = None) -> MessageResult:
        """Start password reset flow.

        If OTP channels exist in the identity list, sends a verification
        code via the selected channel. If ``channel`` is not specified and
        multiple OTP channels exist, uses the first one.
        """
        if not self.has_password_reset:
            raise NotImplementedError("Password reset requires at least one identity with OTP configured")

        user = await self._resolve_user(identifier)
        if user is None:
            return MessageResult(detail="If the account exists, a code has been sent.")

        token = await maybe_await(self.create_reset_token(user))

        # Send OTP via the selected delivery channel
        otp_cfg = self._find_otp_for_channel(channel)
        if otp_cfg is None:
            raise NotImplementedError("No OTP channel found for password reset")

        await self.send_otp_code(identifier, otp_instance=otp_cfg)

        # Issue a pending_reset token to track user through verification
        pending_token = self.token_service.create_access_token(
            str(user.id), _internal_type="pending_reset"
        )
        return MessageResult(detail=f"Verification code sent. Token: {pending_token}")

    async def reset_password_confirm(
        self,
        token: str,
        *,
        channel: str | None = None,
        verification_method: str | None = None,
    ) -> ResetSessionResult | MessageResult:
        """Confirm reset token. If OTP channels exist, sends verification code.

        For backward compat, also supports ``verification_method`` (deprecated, use ``channel``).
        """
        user = await maybe_await(self.validate_reset_token(token))
        if user is None:
            raise UnauthorizedError("Invalid or expired reset token")

        # New identity-driven path: use OTP channels from identity list
        otp_channels = self.otp_channels
        if otp_channels:
            effective_channel = channel or verification_method
            otp_cfg = self._find_otp_for_channel(effective_channel)
            if otp_cfg is None:
                raise NotImplementedError("No OTP channel found")

            identifier = str(getattr(user, "email", getattr(user, "username", "")))
            await self.send_otp_code(identifier, otp_instance=otp_cfg)

            pending_token = self.token_service.create_access_token(
                str(user.id), _internal_type="pending_reset"
            )
            return MessageResult(detail=f"Verification code sent. Token: {pending_token}")

        # Backward compat: ResetablePassword with verification dict
        if isinstance(self.password, ResetablePassword) and self.password.verification is not None:
            verification = self.password.verification
            if isinstance(verification, dict):
                method_key = verification_method
                if method_key is None:
                    raise ValueError(f"verification_method required. Available: {list(verification.keys())}")
                otp_cfg = verification.get(method_key)
                if otp_cfg is None:
                    raise ValueError(f"Unknown verification method: {method_key}")
            else:
                otp_cfg = verification

            identifier = str(getattr(user, "email", getattr(user, "username", "")))
            await self.send_otp_code(identifier, otp_instance=otp_cfg)
            pending_token = self.token_service.create_access_token(
                str(user.id), _internal_type="pending_reset"
            )
            return MessageResult(detail=f"Verification code sent. Token: {pending_token}")

        # No verification — invalidate password immediately
        await maybe_await(self.invalidate_password(user))
        reset_session = self.token_service.create_access_token(
            str(user.id), _internal_type="reset_session",
        )
        return ResetSessionResult(reset_session=reset_session)

    async def reset_password_verify(
        self,
        pending_token: str,
        code: str,
        *,
        channel: str | None = None,
        verification_method: str | None = None,
    ) -> ResetSessionResult:
        """Verify OTP during password reset flow, then return reset session."""
        claims = self.token_service.decode_token(pending_token)
        if claims.get("type") != "pending_reset":
            raise UnauthorizedError("Invalid pending reset token")

        user_id = claims["sub"]
        user = await maybe_await(self.get_user(user_id))
        if user is None:
            raise UnauthorizedError("User not found")

        # Resolve OTP config — identity-driven first, then backward compat
        effective_channel = channel or verification_method
        otp_cfg = self._find_otp_for_channel(effective_channel)

        # Backward compat fallback
        if otp_cfg is None and isinstance(self.password, ResetablePassword) and self.password.verification is not None:
            verification = self.password.verification
            if isinstance(verification, dict):
                if effective_channel is None:
                    raise ValueError("channel is required")
                otp_cfg = verification.get(effective_channel)
            else:
                otp_cfg = verification

        if otp_cfg is None:
            raise ValueError("No OTP configuration found for verification")

        valid = await maybe_await(otp_cfg.verify(user, code))
        if not valid:
            raise UnauthorizedError("Invalid verification code")

        await maybe_await(self.invalidate_password(user))
        reset_session = self.token_service.create_access_token(
            str(user.id), _internal_type="reset_session",
        )
        return ResetSessionResult(reset_session=reset_session)

    async def reset_password_complete(self, reset_session: str, new_password: str) -> MessageResult:
        """Set new password using reset session token."""
        claims = self.token_service.decode_token(reset_session)
        if claims.get("type") != "reset_session":
            raise UnauthorizedError("Invalid reset session")

        user = await maybe_await(self.get_user(claims["sub"]))
        if user is None:
            raise UnauthorizedError("User not found")

        await maybe_await(self.set_password(user, new_password))
        # Revoke all existing tokens for security
        await self.lifecycle.revoke_all(claims["sub"])
        return MessageResult(detail="Password has been reset successfully.")

    async def mfa_challenge(self, mfa_token: str) -> dict[str, Any]:
        """Return available MFA methods for a pending MFA login."""
        claims = self.token_service.decode_token(mfa_token)
        if claims.get("type") != "mfa":
            raise UnauthorizedError("Invalid MFA token")
        user = await maybe_await(self.get_user(claims["sub"]))
        if user is None:
            raise UnauthorizedError("User not found")
        methods = await maybe_await(self.get_mfa_methods(user))
        return {"methods": methods}

    async def mfa_verify(self, mfa_token: str, method: str, code: str) -> AuthResult:
        """Verify MFA code and issue full credentials."""
        claims = self.token_service.decode_token(mfa_token)
        if claims.get("type") != "mfa":
            raise UnauthorizedError("Invalid MFA token")
        user = await maybe_await(self.get_user(claims["sub"]))
        if user is None:
            raise UnauthorizedError("User not found")

        valid = await maybe_await(self.verify_mfa(user, method, code))
        if not valid:
            raise UnauthorizedError("Invalid MFA code")

        pair = await self._issue_tokens(user)
        return AuthResult(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            family_id=pair.family_id,
        )

    async def mfa_enroll_method(self, user: Any, method: str) -> dict[str, Any]:
        """Enroll a user in an MFA method. Returns setup data."""
        return await maybe_await(self.enroll_mfa(user, method))

    # ── Internal helpers ────────────────────────────────────────

    async def issue_for_user(self, user: Any) -> LoginResult:
        """Issue credentials, checking MFA if configured."""
        if self.mfa is not None:
            needs_mfa = self.mfa.required or await maybe_await(self.is_mfa_enrolled(user))
            if needs_mfa:
                mfa_token = self.token_service.create_access_token(
                    str(user.id),
                    extra_claims={"mfa_pending": True},
                    fresh=True,
                    _internal_type="mfa",
                )
                methods = await maybe_await(self.get_mfa_methods(user))
                return MFARequiredResult(mfa_token=mfa_token, methods=methods)

        pair = await self._issue_tokens(user)
        return AuthResult(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            family_id=pair.family_id,
        )

    async def _issue_tokens(self, user: Any) -> IssuedTokenPair:
        """Issue a token pair for a user."""
        roles = await maybe_await(self.get_user_roles(user))
        extra_claims: dict[str, Any] = {}
        if self.namespace is not None:
            extra_claims["ns"] = self.namespace

        return await self.lifecycle.issue(IssueRequest(
            user_id=str(user.id),
            roles=[str(r) for r in roles],
            fresh=True,
            extra_claims=extra_claims or None,
        ))

    # ── Sync wrappers ───────────────────────────────────────────

    def build_context_sync(
        self,
        raw_token: str | None,
        *,
        optional: bool = False,
        request: Any = None,
    ) -> AuthContext:
        """Sync wrapper for ``build_context``."""
        return run_sync(self.build_context(raw_token, optional=optional, request=request))

    def build_context_for_user_sync(self, user: Any, *, request: Any = None) -> AuthContext:
        """Sync wrapper for ``build_context_for_user``."""
        return run_sync(self.build_context_for_user(user, request=request))

    def check_relation_sync(self, user: Any, relation: Relation, resource_id: str) -> bool:
        """Sync wrapper for ``check_relation``."""
        return run_sync(maybe_await(self.check_relation(user, relation, resource_id)))

