/**
 * RateLimiter — simple in-memory rate limiting.
 *
 * Framework adapters turn this into middleware.
 */

export const KeyStrategy = {
  IP: "ip",
  USER: "user",
  IP_AND_USER: "ip+user",
} as const;

export type KeyStrategy = (typeof KeyStrategy)[keyof typeof KeyStrategy];

export interface RateLimiterOptions {
  /** Time window (e.g., "15m", "1h", "60s"). */
  window: string;
  /** Maximum requests per window. */
  max: number;
  /** Key extraction strategy. */
  key?: KeyStrategy;
}

interface WindowEntry {
  count: number;
  resetAt: number;
}

export class RateLimiter {
  private windowMs: number;
  private max: number;
  readonly keyStrategy: KeyStrategy;
  private windows = new Map<string, WindowEntry>();

  constructor(opts: RateLimiterOptions) {
    this.windowMs = parseWindow(opts.window);
    this.max = opts.max;
    this.keyStrategy = opts.key ?? KeyStrategy.IP;
  }

  /** Check if a key is rate-limited. Returns { allowed, remaining, resetAt }. */
  check(key: string): { allowed: boolean; remaining: number; resetAt: number } {
    const now = Date.now();
    let entry = this.windows.get(key);

    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + this.windowMs };
      this.windows.set(key, entry);
    }

    entry.count++;
    const allowed = entry.count <= this.max;
    return {
      allowed,
      remaining: Math.max(0, this.max - entry.count),
      resetAt: entry.resetAt,
    };
  }

  /** Reset rate limit state for a key. */
  reset(key: string): void {
    this.windows.delete(key);
  }
}

function parseWindow(window: string): number {
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(window);
  if (!match) throw new Error(`Invalid window format: "${window}". Use e.g. "15m", "1h", "60s".`);

  const value = parseInt(match[1]!, 10);
  const unit = match[2]!;
  const multipliers: Record<string, number> = {
    ms: 1,
    s: 1000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
  };
  return value * multipliers[unit]!;
}
