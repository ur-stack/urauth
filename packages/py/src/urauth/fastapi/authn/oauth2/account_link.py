"""Multi-provider account linking by verified email."""

from __future__ import annotations

from typing import Any

from urauth.authn.oauth2.client import OAuthUserInfo
from urauth.backends.base import UserFunctions


class AccountLinker:
    """Link OAuth accounts to existing users by verified email, or create new users."""

    def __init__(self, user_fns: UserFunctions) -> None:
        self._user_fns = user_fns

    async def find_or_create(self, info: OAuthUserInfo) -> Any:
        """Match by verified email or delegate to create_oauth_user for creation.

        Returns the user object. If ``create_oauth_user`` is available,
        it will be called for new users; otherwise raises.
        """
        if info.email and info.email_verified:
            user = await self._user_fns.get_by_username(info.email)
            if user is not None:
                return user

        if self._user_fns.create_oauth_user is not None:
            return await self._user_fns.create_oauth_user(info)

        raise LookupError(
            f"No existing user found for {info.provider} ({info.email}), "
            "and no create_oauth_user function is configured"
        )
