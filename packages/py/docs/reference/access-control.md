# Access Control

Checker-based access control for FastAPI. `AccessControl` provides the `guard()` method for creating authorization guards, while the guard classes support dual-use as both `@decorator` and `Depends(guard)`.

## AccessControl

The main entry point for checker-based authorization in FastAPI routes.


> **`urauth.fastapi.authz.access.AccessControl`** — See source code for full API.


## RequirementGuard

A guard that checks composed `Requirement` objects (permissions, roles, relations combined with `&` and `|`).


> **`urauth.fastapi._guards.RequirementGuard`** — See source code for full API.


## RelationGuard

A guard that checks relationship-based access (e.g., resource ownership).


> **`urauth.fastapi._guards.RelationGuard`** — See source code for full API.


## PolicyGuard

A guard that evaluates policy functions against the current `AuthContext`.


> **`urauth.fastapi._guards.PolicyGuard`** — See source code for full API.

