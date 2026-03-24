"""Pipeline-driven auth for FastAPI — strategy resolvers and route generation."""

from urauth.fastapi.pipeline.resolvers import (
    APIKeyResolver,
    BasicAuthResolver,
    FallbackResolver,
    JWTResolver,
    SessionResolver,
    build_resolver,
)
from urauth.fastapi.pipeline.routes import PipelineRouterBuilder

__all__ = [
    "APIKeyResolver",
    "BasicAuthResolver",
    "FallbackResolver",
    "JWTResolver",
    "PipelineRouterBuilder",
    "SessionResolver",
    "build_resolver",
]
