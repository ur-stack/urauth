/**
 * Tenant hierarchy data structures.
 *
 * Defines configurable multi-level tenant hierarchies and the runtime
 * TenantPath that carries hierarchy context through tokens and requests.
 *
 *     const hierarchy = new TenantHierarchy(["organization", "region", "group"]);
 *
 *     const path = new TenantPath([
 *       new TenantNode("acme", "organization"),
 *       new TenantNode("us-west", "region"),
 *     ]);
 *     path.leafId            // "us-west"
 *     path.idAt("organization")  // "acme"
 */

/** A named level in the tenant hierarchy (e.g., 'organization', 'region'). */
export class TenantLevel {
  readonly name: string;
  readonly depth: number;

  constructor(name: string, depth: number) {
    this.name = name;
    this.depth = depth;
  }
}

/** A single segment in a tenant path: a concrete tenant at a specific level. */
export class TenantNode {
  readonly id: string;
  readonly level: string;

  constructor(id: string, level: string) {
    this.id = id;
    this.level = level;
  }
}

/**
 * Ordered path from root to leaf in the tenant hierarchy.
 *
 * Replaces the flat `tenant_id` string with full hierarchy context.
 * The `leafId` property provides backward compatibility with code
 * that expects a single tenant ID string.
 */
export class TenantPath {
  readonly nodes: readonly TenantNode[];

  constructor(nodes: TenantNode[]) {
    this.nodes = Object.freeze([...nodes]);
  }

  /** The most specific tenant ID (last node). Backward-compatible with flat tenant_id. */
  get leafId(): string {
    return this.nodes[this.nodes.length - 1].id;
  }

  /** The level name of the most specific tenant. */
  get leafLevel(): string {
    return this.nodes[this.nodes.length - 1].level;
  }

  /** Get the tenant ID at a specific hierarchy level, or undefined if absent. */
  idAt(level: string): string | undefined {
    for (const node of this.nodes) {
      if (node.level === level) return node.id;
    }
    return undefined;
  }

  /** Check if this path is an ancestor of (or equal to) other. */
  contains(other: TenantPath): boolean {
    if (this.nodes.length > other.nodes.length) return false;
    return this.nodes.every(
      (s, i) => s.id === other.nodes[i].id && s.level === other.nodes[i].level,
    );
  }

  /** Check if any segment in this path has the given tenant ID. */
  isDescendantOf(ancestorId: string): boolean {
    return this.nodes.some((node) => node.id === ancestorId);
  }

  /** Serialize for JWT embedding: `{"organization": "acme", "region": "us-west"}`. */
  toClaim(): Record<string, string> {
    const result: Record<string, string> = {};
    for (const node of this.nodes) {
      result[node.level] = node.id;
    }
    return result;
  }

  /** Deserialize from a JWT claim dict. */
  static fromClaim(claim: Record<string, string>): TenantPath {
    const nodes = Object.entries(claim).map(
      ([level, id]) => new TenantNode(id, level),
    );
    return new TenantPath(nodes);
  }

  /** Wrap a flat tenant_id into a single-node path (backward compat). */
  static fromFlat(tenantId: string, level = "tenant"): TenantPath {
    return new TenantPath([new TenantNode(tenantId, level)]);
  }

  get length(): number {
    return this.nodes.length;
  }

  [Symbol.iterator](): Iterator<TenantNode> {
    return this.nodes[Symbol.iterator]();
  }

  toString(): string {
    const parts = this.nodes.map((n) => `${n.level}:${n.id}`);
    return `TenantPath(${parts.join("/")})`;
  }
}

/**
 * Schema definition for the tenant hierarchy, configured at startup.
 *
 * Accepts either a list of level name strings (auto-numbered by depth)
 * or explicit TenantLevel objects:
 *
 *     new TenantHierarchy(["organization", "region", "group"])
 *     new TenantHierarchy([new TenantLevel("organization", 0), new TenantLevel("region", 1)])
 */
export class TenantHierarchy {
  private _levels: readonly TenantLevel[];
  private _byName: Map<string, TenantLevel>;

  constructor(levels: (string | TenantLevel)[]) {
    const built: TenantLevel[] = levels.map((level, i) =>
      typeof level === "string" ? new TenantLevel(level, i) : level,
    );
    this._levels = Object.freeze(built);
    this._byName = new Map(built.map((lvl) => [lvl.name, lvl]));
  }

  /** Return the depth of a level by name. */
  depthOf(levelName: string): number {
    const lvl = this._byName.get(levelName);
    if (!lvl) throw new Error(`Unknown tenant level: "${levelName}"`);
    return lvl.depth;
  }

  /** Return the parent level name, or undefined for the root level. */
  parentOf(levelName: string): string | undefined {
    const depth = this.depthOf(levelName);
    for (const lvl of this._levels) {
      if (lvl.depth === depth - 1) return lvl.name;
    }
    return undefined;
  }

  /** Return immediate child level names. */
  childrenOf(levelName: string): string[] {
    const depth = this.depthOf(levelName);
    return this._levels.filter((lvl) => lvl.depth === depth + 1).map((lvl) => lvl.name);
  }

  /** Get a level by name, or undefined. */
  get(levelName: string): TenantLevel | undefined {
    return this._byName.get(levelName);
  }

  /** The root (top-most) level. */
  get root(): TenantLevel {
    return this._levels[0];
  }

  /** The leaf (bottom-most) level. */
  get leaf(): TenantLevel {
    return this._levels[this._levels.length - 1];
  }

  get length(): number {
    return this._levels.length;
  }

  [Symbol.iterator](): Iterator<TenantLevel> {
    return this._levels[Symbol.iterator]();
  }

  has(levelName: string): boolean {
    return this._byName.has(levelName);
  }

  toString(): string {
    const names = this._levels.map((lvl) => lvl.name).join(" → ");
    return `TenantHierarchy(${names})`;
  }
}
