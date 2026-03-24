# Primitives

Typed, composable authorization primitives. All primitives support `&` (AND) and `|` (OR) operators to build complex requirements declaratively. For example, `(Permission("task:read") & Role("member")) | Role("admin")` creates a requirement satisfied by either a member with task-read permission or any admin.

## Requirement

The base type for all composable auth requirements.

::: urauth.authz.primitives.Requirement

## Permission

A named permission string, optionally with wildcard matching.

::: urauth.authz.primitives.Permission

## Role

A named role that a user can hold.

::: urauth.authz.primitives.Role

## Relation

A relationship between a user and a resource (e.g., "owner", "member").

::: urauth.authz.primitives.Relation

## Action

An action to be performed on a resource (e.g., "read", "delete").

::: urauth.authz.primitives.Action

## Resource

A named resource that actions are performed on.

::: urauth.authz.primitives.Resource

## AllOf

Requires all contained requirements to be satisfied (AND composition).

::: urauth.authz.primitives.AllOf

## AnyOf

Requires at least one contained requirement to be satisfied (OR composition).

::: urauth.authz.primitives.AnyOf

## PermissionEnum

A typed enum base class for defining permissions statically, providing IDE autocompletion and compile-time safety.

::: urauth.authz.permission_enum.PermissionEnum
