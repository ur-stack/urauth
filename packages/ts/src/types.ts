/** Decoded JWT claims. */
export interface TokenPayload {
  sub: string;
  jti: string;
  iat: number;
  exp: number;
  type: "access" | "refresh";
  scopes?: string[];
  roles?: string[];
  tenant_id?: string;
  fresh?: boolean;
  [key: string]: unknown;
}

/** Authenticated entity for access control. */
export interface Subject {
  id: string;
  roles: string[];
  permissions: string[];
  attributes: Record<string, unknown>;
}
