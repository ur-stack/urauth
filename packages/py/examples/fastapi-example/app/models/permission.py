"""Typed permission definitions using PermissionEnum."""

from __future__ import annotations

from urauth.authz import Action, PermissionEnum, Resource

# ── Resources ────────────────────────────────────────────────
user = Resource("user")
task = Resource("task")

# ── Actions ──────────────────────────────────────────────────
read = Action("read")
write = Action("write")
update = Action("update")
delete = Action("delete")
list_ = Action("list")


class Perms(PermissionEnum):
    """Application permissions — typed, IDE-friendly, string-compatible."""

    USER_READ = (user, read)
    USER_LIST = (user, list_)
    USER_DELETE = (user, delete)
    TASK_READ = (task, read)
    TASK_WRITE = (task, write)
    TASK_UPDATE = (task, update)
    TASK_DELETE = (task, delete)
