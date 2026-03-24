# Access Control

Checker-based access control for FastAPI. `AccessControl` provides the `guard()` method for creating authorization guards, while the guard classes support dual-use as both `@decorator` and `Depends(guard)`.

## AccessControl

The main entry point for checker-based authorization in FastAPI routes.

::: urauth.fastapi.authz.access.AccessControl

## RequirementGuard

A guard that checks composed `Requirement` objects (permissions, roles, relations combined with `&` and `|`).

::: urauth.fastapi._guards.RequirementGuard

## RelationGuard

A guard that checks relationship-based access (e.g., resource ownership).

::: urauth.fastapi._guards.RelationGuard

## PolicyGuard

A guard that evaluates policy functions against the current `AuthContext`.

::: urauth.fastapi._guards.PolicyGuard
