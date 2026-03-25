/**
 * Express error handler for auth errors.
 */

import type { ErrorRequestHandler } from "express";
import { AuthError } from "@urauth/ts";

/**
 * Catches AuthError subclasses and sends appropriate JSON responses.
 *
 * @example
 * ```ts
 * app.use(errorHandler());
 * ```
 */
export function errorHandler(): ErrorRequestHandler {
  return (err, _req, res, next) => {
    if (err instanceof AuthError) {
      res.status(err.statusCode).json({ error: err.detail });
      return;
    }
    next(err);
  };
}
