/** Built-in common actions — mirrors Python's CommonAction enum. */
export const CommonAction = {
  CREATE: "create",
  READ: "read",
  UPDATE: "update",
  DELETE: "delete",
  LIST: "list",
  ARCHIVE: "archive",
} as const;

export type CommonAction = (typeof CommonAction)[keyof typeof CommonAction];

/** Branded type for typed action identifiers. */
export type Action = string & { readonly __brand?: "Action" };

/** Branded type for typed resource identifiers. */
export type Resource = string & { readonly __brand?: "Resource" };
