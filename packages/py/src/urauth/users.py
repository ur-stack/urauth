"""UserDataMixin — base mixin for user data access hooks.

Override methods on an :class:`Auth` subclass, or pass callables directly
to ``Auth(get_user=..., verify_password=...)``. Both sync and async
implementations are supported transparently via ``maybe_await()``.

Mixin composition example::

    from urauth import Auth
    from urauth.contrib.sqlalchemy import SQLAlchemyUserStore

    class MyAuth(Auth, SQLAlchemyUserStore):
        pass

    auth = MyAuth(
        session_factory=async_session_factory,
        user_model=User,
        secret_key="...",
        method=JWT(...),
    )

Subclass example::

    class MyAuth(Auth):
        async def get_user(self, user_id):
            return await db.get(user_id)

        async def get_user_by_username(self, username):
            return await db.get_by_name(username)

        async def verify_password(self, user, password):
            return hasher.verify(password, user.hash)

    auth = MyAuth(method=JWT(...), secret_key="...")

Callable-kwargs example::

    auth = Auth(
        get_user=lambda user_id: USERS_DB.get(str(user_id)),
        get_user_by_username=lambda username: ...,
        verify_password=lambda user, password: ...,
        method=JWT(...),
        secret_key="...",
    )
"""

from __future__ import annotations

from typing import Any

from urauth._async import maybe_await
from urauth.authz.primitives import Permission, Relation, RelationTuple, Role


class UserDataMixin:
    """Hooks for user data access.

    All methods support both sync and async implementations transparently.
    Override on a subclass *or* pass callables to ``Auth(...)`` — both
    patterns are supported.

    Three methods are required (they raise ``NotImplementedError`` by default):
    :meth:`get_user`, :meth:`get_user_by_username`, :meth:`verify_password`.
    All others have sensible defaults.
    """

    # Cooperative init terminator — allows `class MyAuth(Auth, SomeMixin)` without
    # any extra __init__ in MyAuth. Each mixin pops its own kwargs; this one
    # raises if any unexpected kwargs remain (programming error).
    def __init__(self, **kwargs: Any) -> None:
        if kwargs:
            raise TypeError(f"Unexpected keyword arguments: {sorted(kwargs)}")

    # ── Required ─────────────────────────────────────────────────────

    async def get_user(self, user_id: Any) -> Any | None:
        """Load a user by their ID. Must be overridden."""
        raise NotImplementedError("Override get_user() or pass get_user= to Auth()")

    async def get_user_by_username(self, username: str) -> Any | None:
        """Load a user by username. Must be overridden."""
        raise NotImplementedError("Override get_user_by_username() or pass get_user_by_username= to Auth()")

    async def verify_password(self, user: Any, password: str) -> bool:
        """Verify a password against the user's stored hash. Must be overridden."""
        raise NotImplementedError("Override verify_password() or pass verify_password= to Auth()")

    # ── Authorization (optional — safe defaults) ──────────────────────

    async def get_user_roles(self, user: Any) -> list[Role]:
        """Return roles for a user. Default: reads ``user.roles`` attribute."""
        role_names = getattr(user, "roles", [])
        return [Role(name) if isinstance(name, str) else name for name in role_names]

    async def get_user_permissions(self, user: Any) -> list[Permission]:
        """Return direct permissions for a user. Default: empty list."""
        return []

    async def get_user_relations(self, user: Any) -> list[RelationTuple]:
        """Return relation tuples for a user. Default: empty list."""
        return []

    async def check_relation(self, user: Any, relation: Relation, resource_id: str) -> bool:
        """Check if the user has a specific relation to a resource.

        Default delegates to :meth:`get_user_relations` — supports both sync
        and async implementations of that method.
        """
        relations = await maybe_await(self.get_user_relations(user))
        return any(rt.relation == relation and rt.object_id == resource_id for rt in relations)

    # ── Identifier resolution ─────────────────────────────────────────

    async def get_user_by_identifier(self, identifier: str) -> Any | None:
        """Resolve a generic identifier. Default falls back to :meth:`get_user_by_username`."""
        return await maybe_await(self.get_user_by_username(identifier))

    async def get_user_by_email(self, email: str) -> Any | None:
        """Load a user by email. Default falls back to :meth:`get_user_by_identifier`."""
        return await maybe_await(self.get_user_by_identifier(email))

    async def get_user_by_phone(self, phone: str) -> Any | None:
        """Load a user by phone number. Must be overridden to use phone identity."""
        raise NotImplementedError("Override get_user_by_phone() or pass get_user_by_phone= to Auth()")

    async def get_user_by_api_key(self, key: str) -> Any | None:
        """Load a user by API key. Must be overridden to use API key auth."""
        raise NotImplementedError("Override get_user_by_api_key() or pass get_user_by_api_key= to Auth()")

    async def get_or_create_oauth_user(self, info: Any) -> Any | None:
        """Get or create a user from OAuth info. Default: lookup by email/sub."""
        email = getattr(info, "email", None) or getattr(info, "sub", "")
        return await maybe_await(self.get_user_by_username(email))


# Backward compat alias — removed in favour of UserDataMixin.
# Importing UserStore now raises ImportError (hard break, intentional).
__all__ = ["UserDataMixin"]
