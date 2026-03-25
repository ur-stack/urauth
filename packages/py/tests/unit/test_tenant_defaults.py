"""Tests for tenant default role templates."""

from __future__ import annotations

import pytest

from urauth.tenant.defaults import RoleTemplate, TenantDefaults


class TestRoleTemplate:
    def test_creation(self) -> None:
        t = RoleTemplate("admin", permissions=["org:*"], description="Admin role")
        assert t.name == "admin"
        assert t.permissions == ["org:*"]
        assert t.description == "Admin role"

    def test_defaults(self) -> None:
        t = RoleTemplate("member")
        assert t.permissions == []
        assert t.description == ""

    def test_frozen(self) -> None:
        t = RoleTemplate("admin")
        with pytest.raises(AttributeError):
            t.name = "changed"  # type: ignore[misc]


class TestTenantDefaults:
    def test_register_and_retrieve(self) -> None:
        defaults = TenantDefaults()
        templates = [RoleTemplate("admin"), RoleTemplate("member")]
        defaults.register("organization", templates)
        assert defaults.templates_for("organization") == templates

    def test_templates_for_unknown_level(self) -> None:
        defaults = TenantDefaults()
        assert defaults.templates_for("unknown") == []

    def test_register_replaces(self) -> None:
        defaults = TenantDefaults()
        defaults.register("org", [RoleTemplate("old")])
        defaults.register("org", [RoleTemplate("new")])
        assert len(defaults.templates_for("org")) == 1
        assert defaults.templates_for("org")[0].name == "new"

    def test_levels(self) -> None:
        defaults = TenantDefaults()
        defaults.register("organization", [RoleTemplate("admin")])
        defaults.register("group", [RoleTemplate("lead")])
        assert set(defaults.levels) == {"organization", "group"}

    @pytest.mark.asyncio
    async def test_provision_calls_provisioner(self) -> None:
        defaults = TenantDefaults()
        templates = [RoleTemplate("admin", permissions=["org:*"])]
        defaults.register("organization", templates)

        calls: list[tuple[str, str, list[RoleTemplate]]] = []

        class MockProvisioner:
            async def provision(self, tenant_id: str, level: str, tmpls: list[RoleTemplate]) -> None:
                calls.append((tenant_id, level, tmpls))

        await defaults.provision("org-1", "organization", MockProvisioner())  # type: ignore[arg-type]
        assert len(calls) == 1
        assert calls[0] == ("org-1", "organization", templates)

    @pytest.mark.asyncio
    async def test_provision_no_templates_skips(self) -> None:
        defaults = TenantDefaults()

        calls: list[tuple[str, str]] = []

        class MockProvisioner:
            async def provision(self, tenant_id: str, level: str, tmpls: list[RoleTemplate]) -> None:
                calls.append((tenant_id, level))

        await defaults.provision("org-1", "unknown", MockProvisioner())  # type: ignore[arg-type]
        assert len(calls) == 0

    def test_repr(self) -> None:
        defaults = TenantDefaults()
        defaults.register("organization", [RoleTemplate("a"), RoleTemplate("b")])
        assert "organization: 2 templates" in repr(defaults)
