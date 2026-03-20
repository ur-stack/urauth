"""Auto-register OpenAPI security schemes."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI


def register_security_schemes(app: FastAPI, *, api_key_header: str | None = None) -> None:
    """Add security scheme definitions to the OpenAPI spec.

    Call this after all routers are included so the schemes appear in docs.
    """
    schemes: dict[str, Any] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        },
    }

    if api_key_header:
        schemes["ApiKeyAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": api_key_header,
        }

    original = app.openapi

    def custom_openapi() -> dict[str, Any]:
        schema = original()
        components = schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes.update(schemes)

        # Apply globally
        schema.setdefault("security", [])
        for name in schemes:
            entry = {name: []}
            if entry not in schema["security"]:
                schema["security"].append(entry)

        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
