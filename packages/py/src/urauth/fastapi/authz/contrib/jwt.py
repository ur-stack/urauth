"""JWT subject resolver helper."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from starlette.requests import Request

from urauth.authz.exceptions import AccessDeniedError
from urauth.authz.subject import Subject


def jwt_subject_resolver(
    *,
    decode: Callable[[str], dict[str, Any]],
    roles_claim: str = "roles",
    permissions_claim: str = "permissions",
    subject_id_claim: str = "sub",
    attributes_claims: Sequence[str] | None = None,
    token_header: str = "Authorization",
    token_prefix: str = "Bearer",
) -> Callable[[Request], Subject]:
    """Create a subject resolver that extracts Subject from a JWT.

    Args:
        decode: Function to decode/verify a JWT string into a claims dict.
                The caller is responsible for signature verification.
        roles_claim: JWT claim key for roles (default "roles")
        permissions_claim: JWT claim key for permissions (default "permissions")
        subject_id_claim: JWT claim key for subject ID (default "sub")
        attributes_claims: Optional list of claim keys to include as attributes
        token_header: HTTP header containing the token (default "Authorization")
        token_prefix: Token prefix to strip (default "Bearer")

    Returns:
        A sync resolver function: (Request) -> Subject
    """

    def resolver(request: Request) -> Subject:
        auth_header = request.headers.get(token_header, "")

        if token_prefix:
            if not auth_header.startswith(f"{token_prefix} "):
                raise AccessDeniedError("Missing or invalid authorization header")
            token = auth_header[len(token_prefix) + 1 :]
        else:
            token = auth_header

        if not token:
            raise AccessDeniedError("Missing token")

        try:
            claims = decode(token)
        except Exception as e:
            raise AccessDeniedError(f"Invalid token: {e}") from e

        attributes: dict[str, Any] = {}
        if attributes_claims:
            for claim in attributes_claims:
                if claim in claims:
                    attributes[claim] = claims[claim]

        return Subject(
            id=claims.get(subject_id_claim, ""),
            roles=claims.get(roles_claim, []),
            permissions=claims.get(permissions_claim, []),
            attributes=attributes,
        )

    return resolver
