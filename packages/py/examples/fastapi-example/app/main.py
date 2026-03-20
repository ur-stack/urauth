"""FastAPI Task Manager — urauth example application."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.security.auth import auth
from app.core.db.seed import seed_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    await seed_database()
    async with auth.lifespan()(app):
        yield


app = FastAPI(title="urauth Example - Task Manager", lifespan=lifespan)
auth.init_app(app)

app.include_router(api_router)
