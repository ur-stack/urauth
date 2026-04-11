/**
 * collect-docs.ts — Copies per-package docs into the root VitePress docs site.
 *
 * Run: bun scripts/collect-docs.ts
 *
 * For each package that has a docs/ directory, copies its contents into
 * docs/packages/<name>/ and generates a sidebar configuration file at
 * docs/.vitepress/sidebar-generated.ts.
 *
 * Ordered folders and files
 * ─────────────────────────
 * Prefix a folder or file name with a number followed by a dot or hyphen to
 * control sidebar order. The prefix is stripped from the output path and URL.
 *
 *   docs/
 *     01.tutorial/
 *       index.md
 *       01.first-steps.md
 *       02.guards.md
 *     02.how-to/
 *     03.reference/
 *
 * The prefix can use one or more digits and either "." or "-" as separator:
 *   01.name  02-name  003.name
 */

import { existsSync, mkdirSync, rmSync, readdirSync, statSync, copyFileSync, writeFileSync } from "fs";
import { join, basename } from "path";

const ROOT = join(import.meta.dir, "..");
const DOCS_OUT = join(ROOT, "docs", "packages");
const SIDEBAR_OUT = join(ROOT, "docs", ".vitepress", "sidebar-generated.ts");

interface PackageConfig {
  name: string;
  label: string;
  docsDir: string;
}

const packages: PackageConfig[] = [
  { name: "py",      label: "Python",     docsDir: "packages/py/docs" },
  { name: "ts",      label: "TypeScript", docsDir: "packages/ts/docs" },
  { name: "node",    label: "Node.js",    docsDir: "packages/node/docs" },
  { name: "vue",     label: "Vue",        docsDir: "packages/vue/docs" },
  { name: "nuxt",    label: "Nuxt",       docsDir: "packages/nuxt/docs" },
  { name: "react",   label: "React",      docsDir: "packages/react/docs" },
  { name: "next",    label: "Next.js",    docsDir: "packages/next/docs" },
  { name: "hono",    label: "Hono",       docsDir: "packages/hono/docs" },
  { name: "express", label: "Express",    docsDir: "packages/express/docs" },
  { name: "fastify", label: "Fastify",    docsDir: "packages/fastify/docs" },
  { name: "h3",      label: "H3",         docsDir: "packages/h3/docs" },
];

// ── Order-prefix helpers ──────────────────────────────────────────

/** Matches an optional numeric order prefix: "01." "02-" "003." etc. */
const ORDER_PREFIX_RE = /^(\d+)[.\-]/;

/** Strip the order prefix from a file/dir name. */
function stripPrefix(name: string): string {
  return name.replace(ORDER_PREFIX_RE, "");
}

/** Extract the numeric sort key from a file/dir name. Unprefixed entries sort last. */
function sortKey(name: string): number {
  const m = name.match(ORDER_PREFIX_RE);
  return m ? parseInt(m[1], 10) : Infinity;
}

/** Sort directory entries: prefixed ones by their number, then unprefixed ones alphabetically. */
function sortEntries(entries: string[]): string[] {
  return [...entries].sort((a, b) => {
    const ka = sortKey(a);
    const kb = sortKey(b);
    if (ka !== kb) return ka - kb;
    // Both unprefixed (Infinity) — alphabetical
    return stripPrefix(a).localeCompare(stripPrefix(b));
  });
}

// ── File helpers ──────────────────────────────────────────────────

/**
 * Copy a directory recursively, stripping order prefixes from entry names
 * so the output paths are clean.
 */
function copyDirRecursive(src: string, dest: string): void {
  mkdirSync(dest, { recursive: true });
  for (const entry of readdirSync(src)) {
    const srcPath = join(src, entry);
    const destPath = join(dest, stripPrefix(entry));
    if (statSync(srcPath).isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else {
      copyFileSync(srcPath, destPath);
    }
  }
}

/** Derive a display title from a (possibly prefixed) file/dir name. */
function titleFromEntry(entry: string): string {
  // Strip .md before stripPrefix so "01.tutorial" and "01.first-steps.md"
  // both strip cleanly. Using extname() breaks on "01.tutorial" because
  // extname returns ".tutorial" and basename strips the wrong suffix.
  const withoutExt = entry.endsWith(".md") ? entry.slice(0, -3) : entry;
  const clean = stripPrefix(withoutExt);
  if (clean === "index") return "Overview";
  return clean
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

// ── Sidebar building ──────────────────────────────────────────────

interface SidebarItem {
  text: string;
  link?: string;
  items?: SidebarItem[];
  collapsed?: boolean;
}

/**
 * Walk a SOURCE docs directory and build a VitePress sidebar tree.
 *
 * Reads from the source (which may have order prefixes) so that sort order is
 * preserved. URLs are generated from the stripped names, matching the clean
 * paths written by copyDirRecursive.
 */
function buildSidebar(srcDir: string, urlPrefix: string): SidebarItem[] {
  if (!existsSync(srcDir)) return [];

  const all = sortEntries(readdirSync(srcDir));

  const files: string[] = [];
  const dirs: string[] = [];
  for (const entry of all) {
    if (statSync(join(srcDir, entry)).isDirectory()) {
      dirs.push(entry);
    } else if (entry.endsWith(".md")) {
      files.push(entry);
    }
  }

  const items: SidebarItem[] = [];

  // index.md is always the section overview, pinned first
  const indexFile = files.find((f) => stripPrefix(f) === "index.md");
  if (indexFile) {
    items.push({ text: "Overview", link: `${urlPrefix}/` });
  }

  // Other markdown files in sorted order
  for (const file of files) {
    if (stripPrefix(file) === "index.md") continue;
    const cleanName = stripPrefix(basename(file, ".md"));
    items.push({
      text: titleFromEntry(file),
      link: `${urlPrefix}/${cleanName}`,
    });
  }

  // Subdirectories in sorted order
  for (const sub of dirs) {
    const cleanSub = stripPrefix(sub);
    const subItems = buildSidebar(join(srcDir, sub), `${urlPrefix}/${cleanSub}`);
    if (subItems.length > 0) {
      items.push({
        text: titleFromEntry(sub),
        collapsed: true,
        items: subItems,
      });
    }
  }

  return items;
}

// ── Main ──────────────────────────────────────────────────────────

console.log("Collecting docs from packages...");

if (existsSync(DOCS_OUT)) {
  rmSync(DOCS_OUT, { recursive: true });
}
mkdirSync(DOCS_OUT, { recursive: true });

const sidebarSections: Record<string, SidebarItem[]> = {};

for (const pkg of packages) {
  const srcDir = join(ROOT, pkg.docsDir);
  if (!existsSync(srcDir)) {
    console.log(`  [skip] ${pkg.name} — no docs/ directory`);
    continue;
  }

  // Build sidebar from the source directory (has order prefixes → correct sort)
  const sidebar = buildSidebar(srcDir, `/packages/${pkg.name}`);

  // Copy to output with prefixes stripped (clean URLs)
  const destDir = join(DOCS_OUT, pkg.name);
  copyDirRecursive(srcDir, destDir);
  console.log(`  [copy] ${pkg.name} → docs/packages/${pkg.name}/`);

  if (sidebar.length > 0) {
    sidebarSections[pkg.name] = sidebar;
  }
}

// Generate sidebar TypeScript config
const sidebarEntries: string[] = [];
for (const pkg of packages) {
  if (!sidebarSections[pkg.name]) continue;
  sidebarEntries.push(
    `  "/packages/${pkg.name}/": [\n    {\n      text: "${pkg.label}",\n      items: ${JSON.stringify(sidebarSections[pkg.name], null, 8).split("\n").join("\n    ")}\n    }\n  ]`,
  );
}

const sidebarTs = `// Auto-generated by scripts/collect-docs.ts — do not edit manually.
import type { DefaultTheme } from "vitepress";

export const packageSidebars: Record<string, DefaultTheme.SidebarItem[]> = {
${sidebarEntries.join(",\n")}
};
`;

writeFileSync(SIDEBAR_OUT, sidebarTs);
console.log(`  [write] docs/.vitepress/sidebar-generated.ts`);
console.log("Done.");
