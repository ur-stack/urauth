import { describe, test, expect } from "bun:test";
import { PasswordHasher } from "../../src/password";

describe("PasswordHasher Security", () => {
  const hasher = new PasswordHasher({ rounds: 4 }); // low rounds for fast tests

  test("hash is not the original plaintext password", async () => {
    const password = "my-secret-password";
    const hash = await hasher.hash(password);
    expect(hash).not.toBe(password);
    expect(hash.length).toBeGreaterThan(0);
  });

  test("same password hashed twice produces different hashes (salt uniqueness)", async () => {
    const password = "password123";
    const hash1 = await hasher.hash(password);
    const hash2 = await hasher.hash(password);
    expect(hash1).not.toBe(hash2);
  });

  test("correct password verifies successfully", async () => {
    const password = "correct-horse-battery-staple";
    const hash = await hasher.hash(password);
    const result = await hasher.verify(password, hash);
    expect(result).toBe(true);
  });

  test("wrong password fails verification", async () => {
    const password = "correct-password";
    const hash = await hasher.hash(password);
    const result = await hasher.verify("wrong-password", hash);
    expect(result).toBe(false);
  });

  test("similar password fails verification", async () => {
    const password = "password123";
    const hash = await hasher.hash(password);
    const result = await hasher.verify("password124", hash);
    expect(result).toBe(false);
  });

  test("empty password can be hashed and verified", async () => {
    const password = "";
    const hash = await hasher.hash(password);
    expect(hash.length).toBeGreaterThan(0);
    const result = await hasher.verify(password, hash);
    expect(result).toBe(true);
    // Empty password should not verify against non-empty
    const wrongResult = await hasher.verify("notempty", hash);
    expect(wrongResult).toBe(false);
  });

  test("unicode password (emoji, CJK) can be hashed and verified", async () => {
    const emojiPassword = "p@ss\u{1F4A9}\u{1F525}\u{1F680}";
    const hash1 = await hasher.hash(emojiPassword);
    expect(await hasher.verify(emojiPassword, hash1)).toBe(true);
    expect(await hasher.verify("p@ss", hash1)).toBe(false);

    const cjkPassword = "\u4F60\u597D\u4E16\u754C\u5BC6\u7801";
    const hash2 = await hasher.hash(cjkPassword);
    expect(await hasher.verify(cjkPassword, hash2)).toBe(true);
    expect(await hasher.verify("hello", hash2)).toBe(false);
  });

  test("very long password (1000+ chars) does not crash", async () => {
    const longPassword = "a".repeat(1000);
    // bcrypt typically truncates at 72 bytes, but should not crash
    try {
      const hash = await hasher.hash(longPassword);
      expect(hash.length).toBeGreaterThan(0);
      const result = await hasher.verify(longPassword, hash);
      expect(result).toBe(true);
    } catch (err) {
      // If it throws, it should be a clean error, not a segfault/crash
      expect(err).toBeInstanceOf(Error);
    }
  });
});
