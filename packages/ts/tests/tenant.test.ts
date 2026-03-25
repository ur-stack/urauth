import { describe, test, expect } from "bun:test";
import {
  TenantLevel,
  TenantNode,
  TenantPath,
  TenantHierarchy,
  TenantDefaults,
  RoleTemplate,
  AuthContext,
  Permission,
  Role,
} from "../src/index";

describe("TenantPath", () => {
  const path = new TenantPath([
    new TenantNode("acme", "organization"),
    new TenantNode("us-west", "region"),
    new TenantNode("team-alpha", "group"),
  ]);

  test("leafId returns most specific tenant", () => {
    expect(path.leafId).toBe("team-alpha");
  });

  test("leafLevel returns most specific level", () => {
    expect(path.leafLevel).toBe("group");
  });

  test("idAt returns tenant ID at level", () => {
    expect(path.idAt("organization")).toBe("acme");
    expect(path.idAt("region")).toBe("us-west");
    expect(path.idAt("group")).toBe("team-alpha");
    expect(path.idAt("nonexistent")).toBeUndefined();
  });

  test("contains checks ancestor relationship", () => {
    const ancestor = new TenantPath([
      new TenantNode("acme", "organization"),
    ]);
    const sibling = new TenantPath([
      new TenantNode("acme", "organization"),
      new TenantNode("eu-central", "region"),
    ]);

    expect(ancestor.contains(path)).toBe(true);
    expect(path.contains(ancestor)).toBe(false);
    expect(sibling.contains(path)).toBe(false);
  });

  test("isDescendantOf checks any segment", () => {
    expect(path.isDescendantOf("acme")).toBe(true);
    expect(path.isDescendantOf("us-west")).toBe(true);
    expect(path.isDescendantOf("team-alpha")).toBe(true);
    expect(path.isDescendantOf("other-org")).toBe(false);
  });

  test("toClaim serializes for JWT", () => {
    expect(path.toClaim()).toEqual({
      organization: "acme",
      region: "us-west",
      group: "team-alpha",
    });
  });

  test("fromClaim deserializes from JWT", () => {
    const restored = TenantPath.fromClaim({
      organization: "acme",
      region: "us-west",
    });
    expect(restored.leafId).toBe("us-west");
    expect(restored.idAt("organization")).toBe("acme");
  });

  test("fromFlat wraps flat tenant_id", () => {
    const flat = TenantPath.fromFlat("tenant-123");
    expect(flat.leafId).toBe("tenant-123");
    expect(flat.leafLevel).toBe("tenant");
    expect(flat.length).toBe(1);
  });

  test("fromFlat with custom level", () => {
    const flat = TenantPath.fromFlat("org-1", "organization");
    expect(flat.leafLevel).toBe("organization");
  });

  test("length and iteration", () => {
    expect(path.length).toBe(3);
    const levels: string[] = [];
    for (const node of path) {
      levels.push(node.level);
    }
    expect(levels).toEqual(["organization", "region", "group"]);
  });
});

describe("TenantHierarchy", () => {
  test("construction from strings", () => {
    const h = new TenantHierarchy(["organization", "region", "group"]);
    expect(h.length).toBe(3);
    expect(h.root.name).toBe("organization");
    expect(h.leaf.name).toBe("group");
  });

  test("construction from TenantLevel objects", () => {
    const h = new TenantHierarchy([
      new TenantLevel("org", 0),
      new TenantLevel("team", 1),
    ]);
    expect(h.root.name).toBe("org");
    expect(h.leaf.name).toBe("team");
  });

  test("depthOf", () => {
    const h = new TenantHierarchy(["organization", "region", "group"]);
    expect(h.depthOf("organization")).toBe(0);
    expect(h.depthOf("region")).toBe(1);
    expect(h.depthOf("group")).toBe(2);
  });

  test("depthOf throws for unknown level", () => {
    const h = new TenantHierarchy(["org"]);
    expect(() => h.depthOf("unknown")).toThrow("Unknown tenant level");
  });

  test("parentOf", () => {
    const h = new TenantHierarchy(["organization", "region", "group"]);
    expect(h.parentOf("organization")).toBeUndefined();
    expect(h.parentOf("region")).toBe("organization");
    expect(h.parentOf("group")).toBe("region");
  });

  test("childrenOf", () => {
    const h = new TenantHierarchy(["organization", "region", "group"]);
    expect(h.childrenOf("organization")).toEqual(["region"]);
    expect(h.childrenOf("region")).toEqual(["group"]);
    expect(h.childrenOf("group")).toEqual([]);
  });

  test("get", () => {
    const h = new TenantHierarchy(["org", "team"]);
    expect(h.get("org")?.depth).toBe(0);
    expect(h.get("team")?.depth).toBe(1);
    expect(h.get("unknown")).toBeUndefined();
  });

  test("has", () => {
    const h = new TenantHierarchy(["org", "team"]);
    expect(h.has("org")).toBe(true);
    expect(h.has("unknown")).toBe(false);
  });

  test("iteration", () => {
    const h = new TenantHierarchy(["a", "b", "c"]);
    const names: string[] = [];
    for (const level of h) {
      names.push(level.name);
    }
    expect(names).toEqual(["a", "b", "c"]);
  });
});

describe("TenantDefaults", () => {
  test("register and retrieve templates", () => {
    const defaults = new TenantDefaults();
    defaults.register("organization", [
      new RoleTemplate("admin", ["org:*"], "Org admin"),
      new RoleTemplate("member", ["org:read"]),
    ]);

    const templates = defaults.templatesFor("organization");
    expect(templates).toHaveLength(2);
    expect(templates[0]!.name).toBe("admin");
    expect(templates[0]!.permissions).toEqual(["org:*"]);
    expect(templates[0]!.description).toBe("Org admin");
  });

  test("templatesFor returns empty for unregistered level", () => {
    const defaults = new TenantDefaults();
    expect(defaults.templatesFor("unknown")).toEqual([]);
  });

  test("levels returns registered level names", () => {
    const defaults = new TenantDefaults();
    defaults.register("org", [new RoleTemplate("admin")]);
    defaults.register("team", [new RoleTemplate("lead")]);
    expect(defaults.levels).toEqual(["org", "team"]);
  });

  test("provision delegates to provisioner", async () => {
    const defaults = new TenantDefaults();
    defaults.register("org", [
      new RoleTemplate("admin", ["org:*"]),
    ]);

    const calls: Array<{ tenantId: string; level: string; count: number }> = [];
    const provisioner = {
      async provision(tenantId: string, level: string, templates: RoleTemplate[]) {
        calls.push({ tenantId, level, count: templates.length });
      },
    };

    await defaults.provision("org-123", "org", provisioner);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ tenantId: "org-123", level: "org", count: 1 });
  });

  test("provision skips if no templates for level", async () => {
    const defaults = new TenantDefaults();
    const calls: unknown[] = [];
    const provisioner = {
      async provision(...args: unknown[]) { calls.push(args); },
    };

    await defaults.provision("org-123", "unknown", provisioner as any);
    expect(calls).toHaveLength(0);
  });
});

describe("AuthContext tenant integration", () => {
  test("tenantId from TenantPath", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      tenant: new TenantPath([
        new TenantNode("acme", "organization"),
        new TenantNode("us-west", "region"),
      ]),
    });
    expect(ctx.tenantId).toBe("us-west");
  });

  test("tenantId falls back to token.tenant_id", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      token: { sub: "1", jti: "x", iat: 0, exp: 0, type: "access", tenant_id: "flat-tenant" },
    });
    expect(ctx.tenantId).toBe("flat-tenant");
  });

  test("tenantId is undefined when no tenant", () => {
    const ctx = new AuthContext({ user: { id: "1" } });
    expect(ctx.tenantId).toBeUndefined();
  });

  test("inTenant checks hierarchy", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      tenant: new TenantPath([
        new TenantNode("acme", "organization"),
        new TenantNode("us-west", "region"),
      ]),
    });
    expect(ctx.inTenant("acme")).toBe(true);
    expect(ctx.inTenant("us-west")).toBe(true);
    expect(ctx.inTenant("other")).toBe(false);
  });

  test("inTenant returns false without tenant", () => {
    const ctx = new AuthContext({ user: { id: "1" } });
    expect(ctx.inTenant("any")).toBe(false);
  });

  test("atLevel returns tenant ID at level", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      tenant: new TenantPath([
        new TenantNode("acme", "organization"),
        new TenantNode("us-west", "region"),
      ]),
    });
    expect(ctx.atLevel("organization")).toBe("acme");
    expect(ctx.atLevel("region")).toBe("us-west");
    expect(ctx.atLevel("group")).toBeUndefined();
  });

  test("atLevel returns undefined without tenant", () => {
    const ctx = new AuthContext({ user: { id: "1" } });
    expect(ctx.atLevel("any")).toBeUndefined();
  });
});
