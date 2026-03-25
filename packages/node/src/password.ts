/**
 * PasswordHasher — wraps bcrypt/argon2 with a simple interface.
 *
 * Uses dynamic imports so the hashing library is only loaded when needed,
 * and the user only needs to install the one they want.
 */

export interface PasswordHasherOptions {
  algorithm?: "bcrypt" | "argon2";
  rounds?: number;
}

export class PasswordHasher {
  private algorithm: "bcrypt" | "argon2";
  private rounds: number;

  constructor(opts: PasswordHasherOptions = {}) {
    this.algorithm = opts.algorithm ?? "bcrypt";
    this.rounds = opts.rounds ?? 12;
  }

  async hash(password: string): Promise<string> {
    if (this.algorithm === "bcrypt") {
      const bcrypt = await importBcrypt();
      return bcrypt.hash(password, this.rounds);
    }
    const argon2 = await importArgon2();
    return argon2.hash(password);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    if (this.algorithm === "bcrypt") {
      const bcrypt = await importBcrypt();
      return bcrypt.compare(password, hash);
    }
    const argon2 = await importArgon2();
    return argon2.verify(hash, password);
  }
}

interface BcryptLike {
  hash(data: string, rounds: number): Promise<string>;
  compare(data: string, encrypted: string): Promise<boolean>;
}

interface Argon2Like {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
}

/* eslint-disable @typescript-eslint/no-require-imports */
async function importBcrypt(): Promise<BcryptLike> {
  try {
    // Dynamic require for optional peer dependency
    const mod = await (Function('return import("bcrypt")')() as Promise<Record<string, unknown>>);
    return mod.default ? mod.default as unknown as BcryptLike : mod as unknown as BcryptLike;
  } catch {
    try {
      const mod = await (Function('return import("bcryptjs")')() as Promise<Record<string, unknown>>);
      return mod.default ? mod.default as unknown as BcryptLike : mod as unknown as BcryptLike;
    } catch {
      throw new Error(
        'No bcrypt library found. Install "bcrypt" or "bcryptjs": npm install bcrypt',
      );
    }
  }
}

async function importArgon2(): Promise<Argon2Like> {
  try {
    const mod = await (Function('return import("argon2")')() as Promise<Record<string, unknown>>);
    return mod.default ? mod.default as unknown as Argon2Like : mod as unknown as Argon2Like;
  } catch {
    throw new Error(
      'argon2 not found. Install it: npm install argon2',
    );
  }
}
