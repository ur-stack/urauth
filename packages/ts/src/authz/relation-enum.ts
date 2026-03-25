/**
 * defineRelations — declarative Zanzibar relation definitions.
 *
 * TypeScript-idiomatic alternative to Python's RelationEnum.
 *
 * Usage:
 *   const Rels = defineRelations({
 *     DOC_OWNER: "doc#owner",
 *     DOC_VIEWER: ["doc", "viewer"],
 *     FOLDER_EDITOR: new Relation("folder", "editor"),
 *   });
 *   Rels.DOC_OWNER            // Relation instance
 *   Rels.DOC_OWNER.toString() // "doc#owner"
 *   Rels.DOC_OWNER.tuple("readme", "user:alice") // RelationTuple
 */

import { Relation, type RelationParser } from "./primitives";

type RelationDef = string | [string, string] | Relation;
type RelationDefs = Record<string, RelationDef>;

type RelationMap<T extends RelationDefs> = {
  readonly [K in keyof T]: Relation;
};

/** Create a frozen map of named Relation instances. */
export function defineRelations<T extends RelationDefs>(
  defs: T,
  options?: { parser?: RelationParser },
): RelationMap<T> {
  const result = {} as Record<string, Relation>;
  for (const [key, def] of Object.entries(defs)) {
    if (def instanceof Relation) {
      result[key] = def;
    } else if (Array.isArray(def)) {
      result[key] = new Relation(def[0], def[1]);
    } else {
      result[key] = new Relation(def, undefined, { parser: options?.parser });
    }
  }
  return Object.freeze(result) as RelationMap<T>;
}
