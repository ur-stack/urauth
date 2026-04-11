# Primitives

Typed, composable authorization primitives. All primitives support `&` (AND) and `|` (OR) operators to build complex requirements declaratively. For example, `(Permission("task:read") & Role("member")) | Role("admin")` creates a requirement satisfied by either a member with task-read permission or any admin.

`Relation` is resource-first: `Relation("post", "owner")` corresponds to the string form `"post#owner"`. `Permission` is separator-agnostic with auto-detection, so both `"task:read"` and `"task.read"` work transparently.

## Requirement

The base type for all composable auth requirements.


> **`urauth.authz.primitives.Requirement`** — See source code for full API.


## Permission

A named permission string, optionally with wildcard matching.


> **`urauth.authz.primitives.Permission`** — See source code for full API.


## Role

A named role that a user can hold.


> **`urauth.authz.primitives.Role`** — See source code for full API.


## Relation

A relationship between a user and a resource (e.g., "owner", "member").


> **`urauth.authz.primitives.Relation`** — See source code for full API.


## Action

An action to be performed on a resource (e.g., "read", "delete").


> **`urauth.authz.primitives.Action`** — See source code for full API.


## Resource

A named resource that actions are performed on.


> **`urauth.authz.primitives.Resource`** — See source code for full API.


## AllOf

Requires all contained requirements to be satisfied (AND composition).


> **`urauth.authz.primitives.AllOf`** — See source code for full API.


## AnyOf

Requires at least one contained requirement to be satisfied (OR composition).


> **`urauth.authz.primitives.AnyOf`** — See source code for full API.


## RelationTuple

A full Zanzibar relationship tuple binding a relation to a specific object and subject.


> **`urauth.authz.primitives.RelationTuple`** — See source code for full API.


## RelationEnum

A typed enum base class for defining Zanzibar relations statically, providing IDE autocompletion and compile-time safety.


> **`urauth.authz.relation_enum.RelationEnum`** — See source code for full API.


## PermissionEnum

A typed enum base class for defining permissions statically, providing IDE autocompletion and compile-time safety.


> **`urauth.authz.permission_enum.PermissionEnum`** — See source code for full API.

