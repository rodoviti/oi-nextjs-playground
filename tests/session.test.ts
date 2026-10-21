import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeProtectedHeader } from "jose";
import type { JWT } from "next-auth/jwt";
import { decodeSession, encodeSession, SESSION_TTL } from "../src/lib/session";

const secret = "test-only-secret-with-at-least-32-characters";
const salt = "authjs.session-token";
const start = 1_800_000_000;

function claims(): JWT {
  return {
    sub: "test-user",
    level: "L2",
    acr: "https://www.spid.gov.it/SpidL2",
    provider: "spid-l2",
    sessionStartedAt: start,
    sessionExpiresAt: start + SESSION_TTL,
  };
}

afterEach(() => vi.useRealTimers());

describe("absolute JWE session", () => {
  it("encrypts the session with Auth.js and a one-hour deadline", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(start * 1000);
    const token = await encodeSession({ secret, salt, token: claims() });
    expect(token.split(".")).toHaveLength(5);
    expect(decodeProtectedHeader(token)).toMatchObject({ alg: "dir", enc: "A256CBC-HS512" });
    expect(await decodeSession({ secret, salt, token })).toMatchObject({
      sub: "test-user",
      exp: start + 3600,
    });
  });

  it("does not extend the deadline when Auth.js re-encodes the token", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(start * 1000);
    const original = await encodeSession({ secret, salt, token: claims() });
    vi.setSystemTime((start + 1800) * 1000);
    const payload = await decodeSession({ secret, salt, token: original });
    const renewed = await encodeSession({ secret, salt, token: payload! });
    expect(await decodeSession({ secret, salt, token: renewed })).toMatchObject({
      exp: start + 3600,
      sessionStartedAt: start,
    });
    vi.setSystemTime((start + 3599) * 1000);
    expect(await decodeSession({ secret, salt, token: original })).not.toBeNull();
    vi.setSystemTime((start + 3600) * 1000);
    expect(await decodeSession({ secret, salt, token: original })).toBeNull();
    expect(await decodeSession({ secret, salt, token: renewed })).toBeNull();
  });

  it("rejects tampering, wrong secrets and missing expiration", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(start * 1000);
    const token = await encodeSession({ secret, salt, token: claims() });
    await expect(decodeSession({ secret: "wrong-secret", salt, token })).rejects.toThrow();
    const parts = token.split(".");
    parts[3] = `${parts[3][0] === "a" ? "b" : "a"}${parts[3].slice(1)}`;
    await expect(decodeSession({ secret, salt, token: parts.join(".") })).rejects.toThrow();
    const invalid = claims();
    Reflect.deleteProperty(invalid, "sessionExpiresAt");
    await expect(encodeSession({ secret, salt, token: invalid })).rejects.toThrow("expiration");
  });
});
