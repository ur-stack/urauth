"""Session management — list and revoke active login sessions."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException

from app.core.security.auth import auth
from urauth.context import AuthContext

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("/")
async def list_sessions(ctx: AuthContext = Depends(auth.context)):
    """List all active login sessions for the current user.

    Each session groups an access + refresh token pair created at login.
    Shows IP, user-agent, and whether the session is the one making this request.
    """
    user_id = str(ctx.user.id)
    sessions = await auth.token_store.get_sessions(user_id)

    # Determine which family the current request belongs to
    current_family: str | None = None
    if ctx.token:
        current_family = await auth.token_store.get_family_id(ctx.token.jti)

    return [
        {
            "id": s["family_id"],
            "created_at": datetime.fromtimestamp(s["created_at"], tz=UTC).isoformat(),
            "expires_at": datetime.fromtimestamp(s["expires_at"], tz=UTC).isoformat(),
            "ip": s["metadata"].get("ip"),
            "user_agent": s["metadata"].get("user_agent"),
            "current": s["family_id"] == current_family,
        }
        for s in sessions
    ]


@router.delete("/{session_id}", status_code=204)
async def revoke_session(session_id: str, ctx: AuthContext = Depends(auth.context)):
    """Revoke an entire login session (access + refresh tokens).

    Revoking a session means the refresh token can no longer be used
    to obtain new access tokens.
    """
    user_id = str(ctx.user.id)
    sessions = await auth.token_store.get_sessions(user_id)

    if not any(s["family_id"] == session_id for s in sessions):
        raise HTTPException(status_code=404, detail="Session not found")

    await auth.token_store.revoke_family(session_id)
