/** Base authentication/authorization error. */
export class AuthError extends Error {
  public readonly statusCode: number;
  public readonly detail: string;

  constructor(detail = "Authentication error", statusCode = 401) {
    super(detail);
    this.name = "AuthError";
    this.detail = detail;
    this.statusCode = statusCode;
  }
}

export class InvalidTokenError extends AuthError {
  constructor(detail = "Invalid token") {
    super(detail, 401);
    this.name = "InvalidTokenError";
  }
}

export class TokenExpiredError extends AuthError {
  constructor(detail = "Token has expired") {
    super(detail, 401);
    this.name = "TokenExpiredError";
  }
}

export class UnauthorizedError extends AuthError {
  constructor(detail = "Not authenticated") {
    super(detail, 401);
    this.name = "UnauthorizedError";
  }
}

export class ForbiddenError extends AuthError {
  constructor(detail = "Forbidden") {
    super(detail, 403);
    this.name = "ForbiddenError";
  }
}
