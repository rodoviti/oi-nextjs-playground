import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EncryptJWT, jwtDecrypt } from "jose";
import { hkdfSync } from "node:crypto";
import { generateMagicLink, MAGIC_LINK_TTL, redeemMagicLink } from "../src/lib/magic-link";

const state = vi.hoisted(() => ({
  query: vi.fn(), exists: vi.fn(), set: vi.fn(), getDel: vi.fn(),
  authenticate: vi.fn(), createSession: vi.fn(), issueToken: vi.fn(),
  secret: "test-secret-with-more-than-32-characters",
  store: new Map<string, string>(),
}));
vi.mock("../src/lib/database", () => ({ getDatabase: () => ({ query: state.query }) }));
vi.mock("../src/lib/redis", () => ({
  getRedis: async () => ({ exists: state.exists, set: state.set, getDel: state.getDel }),
}));
vi.mock("../src/lib/jwt", async (original) => ({
  ...await original<typeof import("../src/lib/jwt")>(),
  appOrigin: async () => "https://app.example",
  authenticate: state.authenticate,
  issueToken: state.issueToken,
  tokenAuthContext: async () => ({
    secret: state.secret, internalAdapter: { createSession: state.createSession },
  }),
}));
const start = 1_800_000_000;
const source = {
  id: "source", userId: "user-id", subject: "subject", issuer: "https://idp.example",
  level: "L3", provider: "spid-l3", acr: "spid-l3",
  createdAt: new Date(start * 1000), expiresAt: new Date((start + 3600) * 1000), revokedAt: null,
};
const request = new Request("https://app.example/api/magic-link/generate");
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(start * 1000);
  state.store.clear();
  state.query.mockReset().mockResolvedValue({ rows: [source] });
  state.exists.mockReset().mockResolvedValue(0);
  state.authenticate.mockReset().mockResolvedValue({ session: { id: source.id, user: { id: source.subject } } });
  state.createSession.mockReset().mockResolvedValue({ id: "new-session" });
  state.issueToken.mockReset().mockResolvedValue({ token: "signed-jwt", session: { provider: "magic-link" } });
  state.set.mockReset().mockImplementation(async (key: string, value: string) => {
    state.store.set(key, value); return "OK";
  });
  state.getDel.mockReset().mockImplementation(async (key: string) => {
    const value = state.store.get(key);
    state.store.delete(key);
    return value ?? null;
  });
});
afterEach(() => vi.useRealTimers());

describe("Magic-link authentication provider", () => {
  it("encrypts a 24-hour credential with domain-separated BETTER_AUTH_SECRET", async () => {
    const result = await generateMagicLink(request);
    const key = new Uint8Array(hkdfSync("sha256", state.secret, "oi-nextjs-playground", "magic-link", 32));
    const { payload, protectedHeader } = await jwtDecrypt(result.jwe, key);
    expect(protectedHeader).toEqual({ alg: "dir", enc: "A256GCM", typ: "magic-link+jwe" });
    expect(payload).toMatchObject({
      sid: "source", sub: "subject", purpose: "magic-link",
      iss: "https://app.example", aud: "https://app.example/api/magic-link",
      iat: start, exp: start + MAGIC_LINK_TTL,
    });
    expect(result.expiresAt).toBe(new Date((start + MAGIC_LINK_TTL) * 1000).toISOString());
    expect(state.authenticate).toHaveBeenCalledWith(request);
  });

  it("redeems after source expiry into an independent one-hour session without SPID claims", async () => {
    const { jwe } = await generateMagicLink(request);
    vi.setSystemTime((start + 7200) * 1000);
    expect(await redeemMagicLink(jwe)).toMatchObject({ token: "signed-jwt" });
    expect(state.createSession).toHaveBeenCalledWith("user-id", false, {
      subject: source.subject, issuer: source.issuer, provider: "magic-link",
      level: null, acr: null, authTime: null,
      createdAt: new Date((start + 7200) * 1000), updatedAt: new Date((start + 7200) * 1000),
      expiresAt: new Date((start + 10800) * 1000),
    }, true);
    expect(state.issueToken).toHaveBeenCalledWith("new-session");
    await expect(redeemMagicLink(jwe)).rejects.toMatchObject({ status: 401 });
  });

  it("permits only one concurrent redemption", async () => {
    const { jwe } = await generateMagicLink(request);
    const results = await Promise.allSettled([redeemMagicLink(jwe), redeemMagicLink(jwe)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(state.createSession).toHaveBeenCalledTimes(1);
  });

  it("rejects at the exact expiry and rejects tampered ciphertext", async () => {
    const { jwe } = await generateMagicLink(request);
    const parts = jwe.split(".");
    parts[3] = (parts[3][0] === "A" ? "B" : "A") + parts[3].slice(1);
    await expect(redeemMagicLink(parts.join("."))).rejects.toMatchObject({ status: 401 });
    vi.setSystemTime((start + MAGIC_LINK_TTL) * 1000);
    await expect(redeemMagicLink(jwe)).rejects.toMatchObject({ status: 401 });
    expect(state.createSession).not.toHaveBeenCalled();
  });

  it.each(["database-revocation", "redis-revocation", "missing-source", "different-subject"])(
    "rejects %s without consuming a link", async (mode) => {
      const { jwe } = await generateMagicLink(request);
      if (mode === "database-revocation") state.query.mockResolvedValue({ rows: [{ ...source, revokedAt: new Date() }] });
      if (mode === "redis-revocation") state.exists.mockResolvedValue(1);
      if (mode === "missing-source") state.query.mockResolvedValue({ rows: [] });
      if (mode === "different-subject") state.query.mockResolvedValue({ rows: [{ ...source, subject: "other" }] });
      await expect(redeemMagicLink(jwe)).rejects.toMatchObject({ status: 401 });
      expect(state.getDel).not.toHaveBeenCalled();
      expect(state.createSession).not.toHaveBeenCalled();
    },
  );

  it("fails closed on infrastructure errors and burns a link if session creation fails", async () => {
    const { jwe } = await generateMagicLink(request);
    state.getDel.mockRejectedValueOnce(new Error("Redis unavailable"));
    await expect(redeemMagicLink(jwe)).rejects.toThrow("Redis unavailable");
    expect(state.createSession).not.toHaveBeenCalled();
    state.createSession.mockRejectedValueOnce(new Error("DB unavailable"));
    await expect(redeemMagicLink(jwe)).rejects.toThrow("DB unavailable");
    await expect(redeemMagicLink(jwe)).rejects.toMatchObject({ status: 401 });
  });

  it("rejects wrong purpose, issuer, audience, algorithm, future issuance and lifetimes", async () => {
    const key = new Uint8Array(hkdfSync("sha256", state.secret, "oi-nextjs-playground", "magic-link", 32));
    for (const overrides of [
      { purpose: "other" }, { iss: "https://evil.example" }, { aud: "other" },
      { iat: start + 1 }, { exp: start + MAGIC_LINK_TTL + 1 },
    ]) {
      const jwe = await new EncryptJWT({
        sub: "subject", sid: "source", jti: "id", iat: start, exp: start + MAGIC_LINK_TTL,
        iss: "https://app.example", aud: "https://app.example/api/magic-link",
        purpose: "magic-link", ...overrides,
      }).setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "magic-link+jwe" }).encrypt(key);
      await expect(redeemMagicLink(jwe)).rejects.toMatchObject({ status: 401 });
    }
    const wrongAlgorithm = await new EncryptJWT({}).setProtectedHeader({ alg: "dir", enc: "A128GCM" }).encrypt(key.slice(0, 16));
    await expect(redeemMagicLink(wrongAlgorithm)).rejects.toMatchObject({ status: 401 });
    await expect(redeemMagicLink("invalid")).rejects.toMatchObject({ status: 400 });
    expect(state.createSession).not.toHaveBeenCalled();
  });
});
