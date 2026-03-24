# pyright: reportUnknownMemberType=false
from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
from jwt.types import Options

from urauth.config import AuthConfig
from urauth.exceptions import InvalidTokenError, TokenExpiredError
from urauth.types import TokenPair, TokenPayload


class TokenService:
    """Create and validate JWTs using PyJWT."""

    def __init__(self, config: AuthConfig) -> None:
        self._config = config
        self._key = self._build_key(config)

    @staticmethod
    def _build_key(config: AuthConfig) -> str | bytes:
        """Return the signing key. PyJWT accepts PEM strings for RSA/EC
        and str/bytes for HMAC directly — no wrapper objects needed."""
        return config.secret_key

    def _base_claims(
        self,
        user_id: str,
        token_type: str,
        ttl: int,
        jti: str | None = None,
    ) -> dict[str, Any]:
        now = time.time()
        claims: dict[str, Any] = {
            "sub": str(user_id),
            "jti": jti or uuid.uuid4().hex,
            "iat": now,
            "exp": now + ttl,
            "type": token_type,
        }
        if self._config.token_issuer:
            claims["iss"] = self._config.token_issuer
        if self._config.token_audience:
            claims["aud"] = self._config.token_audience
        return claims

    def create_access_token(
        self,
        user_id: str,
        *,
        scopes: list[str] | None = None,
        roles: list[str] | None = None,
        tenant_id: str | None = None,
        fresh: bool = False,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        claims = self._base_claims(user_id, "access", self._config.access_token_ttl)
        if scopes:
            claims["scopes"] = scopes
        if roles:
            claims["roles"] = roles
        if tenant_id:
            claims["tenant_id"] = tenant_id
        if fresh:
            claims["fresh"] = True
        if extra_claims:
            reserved = {"sub", "jti", "iat", "exp", "iss", "aud"}
            claims.update({k: v for k, v in extra_claims.items() if k not in reserved})

        return jwt.encode(claims, self._key, algorithm=self._config.algorithm)

    def create_refresh_token(
        self,
        user_id: str,
        *,
        family_id: str | None = None,
    ) -> str:
        claims = self._base_claims(user_id, "refresh", self._config.refresh_token_ttl)
        if family_id:
            claims["family_id"] = family_id
        return jwt.encode(claims, self._key, algorithm=self._config.algorithm)

    def create_token_pair(
        self,
        user_id: str,
        *,
        scopes: list[str] | None = None,
        roles: list[str] | None = None,
        tenant_id: str | None = None,
        fresh: bool = False,
        extra_claims: dict[str, Any] | None = None,
        family_id: str | None = None,
    ) -> TokenPair:
        access = self.create_access_token(
            user_id,
            scopes=scopes,
            roles=roles,
            tenant_id=tenant_id,
            fresh=fresh,
            extra_claims=extra_claims,
        )
        refresh = self.create_refresh_token(user_id, family_id=family_id)
        return TokenPair(access_token=access, refresh_token=refresh)

    def decode_token(self, token: str) -> dict[str, Any]:
        """Decode and verify a JWT, returning raw claims dict."""
        options = Options()
        kwargs: dict[str, Any] = {"algorithms": [self._config.algorithm]}
        if self._config.token_issuer:
            kwargs["issuer"] = self._config.token_issuer
        if self._config.token_audience:
            kwargs["audience"] = self._config.token_audience
        else:
            options["verify_aud"] = False
        try:
            claims: dict[str, Any] = jwt.decode(token, self._key, options=options, **kwargs)
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError() from exc
        except (jwt.InvalidIssuerError, jwt.InvalidAudienceError) as exc:
            raise InvalidTokenError(f"Invalid issuer or audience: {exc}") from exc
        except jwt.InvalidTokenError as exc:
            raise InvalidTokenError(f"Invalid token: {exc}") from exc
        return claims

    def validate_access_token(self, token: str) -> TokenPayload:
        """Decode, verify, and return a typed TokenPayload for an access token."""
        claims = self.decode_token(token)
        if claims.get("type") != "access":
            raise InvalidTokenError("Not an access token")
        try:
            sub = claims["sub"]
            jti = claims["jti"]
            iat = claims["iat"]
            exp = claims["exp"]
        except KeyError as exc:
            raise InvalidTokenError(f"Missing required claim: {exc}") from exc
        return TokenPayload(
            sub=sub,
            jti=jti,
            iat=iat,
            exp=exp,
            token_type="access",
            scopes=claims.get("scopes", []),
            roles=claims.get("roles", []),
            tenant_id=claims.get("tenant_id"),
            fresh=claims.get("fresh", False),
            extra={
                k: v
                for k, v in claims.items()
                if k
                not in {
                    "sub",
                    "jti",
                    "iat",
                    "exp",
                    "type",
                    "scopes",
                    "roles",
                    "tenant_id",
                    "fresh",
                    "iss",
                    "aud",
                }
            },
        )

    def validate_refresh_token(self, token: str) -> dict[str, Any]:
        """Decode and verify a refresh token, returning raw claims."""
        claims = self.decode_token(token)
        if claims.get("type") != "refresh":
            raise InvalidTokenError("Not a refresh token")
        return claims
