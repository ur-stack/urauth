# AuthContext

The single identity model used throughout urauth. `AuthContext` carries the authenticated user, their roles, permissions, relations, scopes, the current token, the tenant hierarchy path, and the originating request. Guards, checkers, and application code all operate on this one type.

The `relations` field is typed as `list[RelationTuple]`, where each `RelationTuple` binds a `Relation` to a specific object and subject (Zanzibar-style). This replaces the previous `list[tuple[Relation, str]]` representation.

Key tenant-related fields and methods:

- `tenant` -- the resolved `TenantPath` (or `None`)
- `tenant_id` -- property returning the leaf tenant ID (backward compat)
- `in_tenant(id)` -- check if the context is within a specific tenant at any level
- `at_level(level)` -- get the tenant ID at a specific hierarchy level


> **`urauth.context.AuthContext`** — See source code for full API.

