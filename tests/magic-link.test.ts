import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateMagicLink, MAGIC_LINK_TTL, redeemMagicLink } from "../src/lib/magic-link";

type Verification = { identifier: string; value: string; expiresAt: Date };
const state = vi.hoisted(() => ({
  query: vi.fn(), exists: vi.fn(),
  authenticate: vi.fn(), createSession: vi.fn(), issueToken: vi.fn(),
  createVerificationValue: vi.fn(), consumeVerificationValue: vi.fn(),
  store: new Map<string, Verification>(),
}));
vi.mock("../src/lib/database", () => ({ getDatabase: () => ({ query: state.query }) }));
vi.mock("../src/lib/redis", () => ({
  getRedis: async () => ({ exists: state.exists }),
}));
vi.mock("../src/lib/jwt", async (original) => ({
  ...await original<typeof import("../src/lib/jwt")>(),
  authenticate: state.authenticate,
  issueToken: state.issueToken,
  tokenAuthContext: async () => ({
    internalAdapter: {
      createSession: state.createSession,
      createVerificationValue: state.createVerificationValue,
      consumeVerificationValue: state.consumeVerificationValue,
    },
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
  state.createVerificationValue.mockReset().mockImplementation(async (record: Verification) => {
    state.store.set(record.identifier, record);
    return record;
  });
  state.consumeVerificationValue.mockReset().mockImplementation(async (key: string) => {
    const record = state.store.get(key);
    state.store.delete(key);
    return record && record.expiresAt.getTime() >= Date.now() ? record : null;
  });
});
afterEach(() => vi.useRealTimers());

describe("Magic-link authentication provider", () => {
  it("stores only a hash of a random 256-bit credential through Better Auth verification", async () => {
    const result = await generateMagicLink(request);
    expect(result.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const identifier = `magic-link:${createHash("sha256").update(result.token).digest("hex")}`;
    expect(state.createVerificationValue).toHaveBeenCalledWith({
      identifier, value: JSON.stringify({ sessionId: "source", subject: "subject" }),
      expiresAt: new Date((start + MAGIC_LINK_TTL) * 1000),
    });
    expect(JSON.stringify([...state.store.values()])).not.toContain(result.token);
    expect(result.expiresAt).toBe(new Date((start + MAGIC_LINK_TTL) * 1000).toISOString());
    expect(state.authenticate).toHaveBeenCalledWith(request);
    expect((await generateMagicLink(request)).token).not.toBe(result.token);
  });

  it("redeems after source expiry into an independent one-hour session without SPID claims", async () => {
    const { token } = await generateMagicLink(request);
    vi.setSystemTime((start + 7200) * 1000);
    expect(await redeemMagicLink(token)).toMatchObject({ token: "signed-jwt" });
    expect(state.createSession).toHaveBeenCalledWith("user-id", false, {
      subject: source.subject, issuer: source.issuer, provider: "magic-link",
      level: null, acr: null, authTime: null,
      createdAt: new Date((start + 7200) * 1000), updatedAt: new Date((start + 7200) * 1000),
      expiresAt: new Date((start + 10800) * 1000),
    }, true);
    expect(state.issueToken).toHaveBeenCalledWith("new-session");
    await expect(redeemMagicLink(token)).rejects.toMatchObject({ status: 401 });
  });

  it("permits only one concurrent redemption", async () => {
    const { token } = await generateMagicLink(request);
    const results = await Promise.allSettled([redeemMagicLink(token), redeemMagicLink(token)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(state.createSession).toHaveBeenCalledTimes(1);
  });

  it.each([MAGIC_LINK_TTL, MAGIC_LINK_TTL + 1])("rejects at expiry plus %i seconds", async (elapsed) => {
    const { token } = await generateMagicLink(request);
    vi.setSystemTime((start + elapsed) * 1000);
    await expect(redeemMagicLink(token)).rejects.toMatchObject({ status: 401 });
    expect(state.createSession).not.toHaveBeenCalled();
  });

  it("accepts immediately before the exact expiry boundary", async () => {
    const { token } = await generateMagicLink(request);
    vi.setSystemTime((start + MAGIC_LINK_TTL) * 1000 - 1);
    await expect(redeemMagicLink(token)).resolves.toMatchObject({ token: "signed-jwt" });
  });

  it.each(["database-revocation", "redis-revocation", "missing-source", "different-subject"])(
    "rejects %s without creating a session", async (mode) => {
      const { token } = await generateMagicLink(request);
      if (mode === "database-revocation") state.query.mockResolvedValue({ rows: [{ ...source, revokedAt: new Date() }] });
      if (mode === "redis-revocation") state.exists.mockResolvedValue(1);
      if (mode === "missing-source") state.query.mockResolvedValue({ rows: [] });
      if (mode === "different-subject") state.query.mockResolvedValue({ rows: [{ ...source, subject: "other" }] });
      await expect(redeemMagicLink(token)).rejects.toMatchObject({ status: 401 });
      expect(state.createSession).not.toHaveBeenCalled();
      expect(state.store.size).toBe(0);
    },
  );

  it("propagates verification storage failures instead of returning a credential", async () => {
    state.createVerificationValue.mockRejectedValueOnce(new Error("DB unavailable"));
    await expect(generateMagicLink(request)).rejects.toThrow("DB unavailable");
    state.createVerificationValue.mockResolvedValueOnce(null);
    await expect(generateMagicLink(request)).rejects.toThrow("Unable to store");
    state.authenticate.mockRejectedValueOnce(new Error("Invalid bearer"));
    await expect(generateMagicLink(request)).rejects.toThrow("Invalid bearer");
  });

  it("fails closed on consume errors and burns the token if session creation fails", async () => {
    const { token } = await generateMagicLink(request);
    state.consumeVerificationValue.mockRejectedValueOnce(new Error("DB unavailable"));
    await expect(redeemMagicLink(token)).rejects.toThrow("DB unavailable");
    expect(state.createSession).not.toHaveBeenCalled();
    state.createSession.mockRejectedValueOnce(new Error("Session creation failed"));
    await expect(redeemMagicLink(token)).rejects.toThrow("Session creation failed");
    await expect(redeemMagicLink(token)).rejects.toMatchObject({ status: 401 });
  });

  it("fails closed when Redis revocation state is unavailable", async () => {
    const { token } = await generateMagicLink(request);
    state.exists.mockRejectedValueOnce(new Error("Redis unavailable"));
    await expect(redeemMagicLink(token)).rejects.toThrow("Redis unavailable");
    expect(state.createSession).not.toHaveBeenCalled();
  });

  it("rejects malformed, unknown and altered credentials", async () => {
    for (const value of [undefined, null, "", "invalid", "x".repeat(44), ".".repeat(43)]) {
      await expect(redeemMagicLink(value)).rejects.toMatchObject({ status: 400 });
    }
    expect(state.consumeVerificationValue).not.toHaveBeenCalled();
    const { token } = await generateMagicLink(request);
    const altered = (token[0] === "A" ? "B" : "A") + token.slice(1);
    await expect(redeemMagicLink(altered)).rejects.toMatchObject({ status: 401 });
    await expect(redeemMagicLink("x".repeat(43))).rejects.toMatchObject({ status: 401 });
    expect(state.createSession).not.toHaveBeenCalled();
  });

  it("surfaces corrupt stored verification data as an infrastructure error", async () => {
    for (const value of ["invalid-json", "{}", '{"sessionId":123,"subject":"subject"}']) {
      const { token } = await generateMagicLink(request);
      const record = [...state.store.values()][0];
      record.value = value;
      await expect(redeemMagicLink(token)).rejects.toThrow();
    }
    expect(state.createSession).not.toHaveBeenCalled();
  });
});
