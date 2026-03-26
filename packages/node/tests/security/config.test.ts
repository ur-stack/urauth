import { describe, test, expect } from "bun:test";
import { validateConfig } from "../../src/config";
import type { AuthConfig } from "../../src/config";

describe("Config Validation Security", () => {
  test("empty secretKey throws", () => {
    expect(() =>
      validateConfig({ secretKey: "" } as AuthConfig),
    ).toThrow("secretKey must not be empty");
  });

  test("whitespace-only secretKey throws", () => {
    expect(() =>
      validateConfig({ secretKey: "   " } as AuthConfig),
    ).toThrow("secretKey must not be empty");
  });

  test("default key without allowInsecureKey throws", () => {
    expect(() =>
      validateConfig({
        secretKey: "CHANGE-ME-IN-PRODUCTION",
        environment: "development",
      }),
    ).toThrow("default");
  });

  test("default key in production always throws even with allowInsecureKey", () => {
    expect(() =>
      validateConfig({
        secretKey: "CHANGE-ME-IN-PRODUCTION",
        environment: "production",
        allowInsecureKey: true,
      }),
    ).toThrow();
  });

  test("production + allowInsecureKey throws", () => {
    expect(() =>
      validateConfig({
        secretKey: "a-perfectly-fine-secret-key-that-is-long-enough-ok",
        environment: "production",
        allowInsecureKey: true,
      }),
    ).toThrow("allowInsecureKey cannot be true in production");
  });

  test("short HMAC key (<32 chars) without allowInsecureKey throws", () => {
    expect(() =>
      validateConfig({
        secretKey: "short-key",
        environment: "development",
      }),
    ).toThrow("at least 32 characters");
  });

  test("weak secrets from blocklist throw without allowInsecureKey", () => {
    const weakSecrets = [
      "secret",
      "password",
      "changeme",
      "test",
      "key",
      "admin",
      "123456",
      "jwt-secret",
      "my-secret",
      "super-secret",
    ];
    for (const weak of weakSecrets) {
      expect(() =>
        validateConfig({
          secretKey: weak,
          environment: "development",
        }),
      ).toThrow();
    }
  });

  test("testing environment auto-allows insecure keys", () => {
    // Should not throw — testing environment implicitly allows insecure keys
    expect(() =>
      validateConfig({
        secretKey: "short",
        environment: "testing",
      }),
    ).not.toThrow();
  });

  test("valid 32+ char key passes", () => {
    expect(() =>
      validateConfig({
        secretKey: "this-is-a-valid-secret-key-that-is-long-enough",
        environment: "production",
      }),
    ).not.toThrow();
  });
});
