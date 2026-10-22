import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from "jose";
import { apiResponse, authenticate, HttpError, issueToken, revokeSession } from "../src/lib/jwt";

const state = vi.hoisted(() => ({
  jwks: { keys: [] } as JSONWebKeySet,
  exists: vi.fn(),
  set: vi.fn(),
  query: vi.fn(),
  signJWT: vi.fn(),
}));
vi.mock("../src/lib/database", () => ({ getDatabase: () => ({ query: state.query }) }));
vi.mock("../src/lib/redis", () => ({ getRedis: async () => ({ exists: state.exists, set: state.set }) }));
vi.mock("better-auth", () => ({
  betterAuth: () => ({
    $context: Promise.resolve({ baseURL: "https://app.example.test/api/auth" }),
    api: { getJwks: async () => state.jwks, signJWT: state.signJWT },
  }),
}));

const start = 1_800_000_000;
const session = {
  id: "session-id",
  user: { id: "oidc-user", name: "Utente", email: "demo@example.test" },
  level: "L2", acr: "https://www.spid.gov.it/SpidL2", provider: "spid-l2",
  startedAt: new Date(start * 1000).toISOString(),
  expires: new Date((start + 3600) * 1000).toISOString(),
};
let privateKey: CryptoKey;
beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  state.jwks = { keys: [{ ...await exportJWK(pair.publicKey), alg: "RS256", kid: "test-key" }] };
});
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(start * 1000);
  state.exists.mockReset().mockResolvedValue(0);
  state.set.mockReset().mockResolvedValue("OK");
  state.query.mockReset().mockResolvedValue({ rows: [] });
  state.signJWT.mockReset().mockResolvedValue({ token: "signed-by-better-auth" });
});
afterEach(() => vi.useRealTimers());

async function signed(overrides: Record<string, unknown> = {}) {
  return new SignJWT({
    sub: "oidc-user", sid: "session-id", jti: "token-id",
    iat: start, exp: start + 3600, iss: "https://app.example.test",
    aud: "https://app.example.test", session, ...overrides,
  }).setProtectedHeader({ alg: "RS256", kid: "test-key" }).sign(privateKey);
}
function request(token: string) {
  return new Request("https://app.example.test/api/example", {
    headers: { Authorization: `Bearer ${token}` },
  });
}

describe("Asymmetric bearer verification and revocation", () => {
  it("validates signature and checks Redis on every request without renewing expiry", async () => {
    const token = await signed();
    for (const elapsed of [0, 1800, 3599]) {
      vi.setSystemTime((start + elapsed) * 1000);
      expect((await authenticate(request(token))).session).toEqual(session);
    }
    expect(state.exists).toHaveBeenCalledTimes(3);
    expect(state.exists).toHaveBeenCalledWith("revoked:session-id");
    expect(state.set).not.toHaveBeenCalled();
    vi.setSystemTime((start + 3600) * 1000);
    await expect(authenticate(request(token))).rejects.toMatchObject({ status: 401 });
  });
  it.each([
    { iss: "https://evil.example" }, { aud: "other-api" },
    { exp: start - 1 }, { exp: start + 7200 }, { iat: start + 1 },
    { sid: "other-session" }, { sub: "other-user" }, { session: { ...session, level: "L1" } },
  ])("rejects invalid signed claims %j", async (overrides) => {
    await expect(authenticate(request(await signed(overrides)))).rejects.toMatchObject({ status: 401 });
  });
  it("rejects malformed tokens and cookie-only authentication", async () => {
    await expect(authenticate(request("malformed"))).rejects.toMatchObject({ status: 401 });
    await expect(authenticate(new Request("https://app.example.test/api/example", {
      headers: { Cookie: "better-auth.session_token=opaque" },
    }))).rejects.toMatchObject({ status: 401 });
  });
  it("rejects all JWTs for a revoked session", async () => {
    state.exists.mockResolvedValue(1);
    await expect(authenticate(request(await signed()))).rejects.toMatchObject({ status: 401 });
    await expect(authenticate(request(await signed({ jti: "another-token" })))).rejects.toMatchObject({ status: 401 });
  });
  it("writes revocation before marking the DB record, preserving the absolute deadline", async () => {
    await revokeSession("session-id", start + 3600);
    expect(state.set).toHaveBeenCalledWith("revoked:session-id", "1", { EXAT: start + 3600 });
    expect(state.set.mock.invocationCallOrder[0]).toBeLessThan(state.query.mock.invocationCallOrder[0]);
    expect(state.query).toHaveBeenCalledWith(expect.stringContaining('"revokedAt"'), ["session-id"]);
  });
  it("fails closed on Redis errors and never reports successful logout", async () => {
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const token = await signed();
      state.exists.mockRejectedValue(new Error("Redis unavailable"));
      expect((await apiResponse(async () => Response.json(await authenticate(request(token))))).status).toBe(503);
      state.set.mockRejectedValue(new Error("Redis unavailable"));
      const response = await apiResponse(async () => {
        await revokeSession("session-id", start + 3600);
        return new Response(null, { status: 204 });
      });
      expect(response.status).toBe(503);
      expect(state.query).not.toHaveBeenCalled();
      expect(diagnostic).toHaveBeenCalledTimes(2);
    } finally {
      diagnostic.mockRestore();
    }
  });
  it("returns no-store and a Bearer challenge for invalid credentials", async () => {
    const response = await apiResponse(async () => { throw new HttpError(401, "Invalid"); });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("www-authenticate")).toBe("Bearer");
  });
  it("uses Better Auth signing with the session's original iat/exp", async () => {
    vi.setSystemTime((start + 1800) * 1000);
    state.query.mockResolvedValue({ rows: [{
      id: "session-id", userId: "internal-user", subject: "oidc-user",
      issuer: "https://idp.example.test", level: "L2", acr: session.acr,
      provider: "spid-l2", createdAt: new Date(start * 1000),
      expiresAt: new Date((start + 3600) * 1000), revokedAt: null,
      name: "Utente", email: "demo@example.test",
    }] });
    expect((await issueToken("session-id")).token).toBe("signed-by-better-auth");
    expect(state.signJWT).toHaveBeenCalledWith({
      body: { payload: expect.objectContaining({ sid: "session-id", iat: start, exp: start + 3600 }) },
    });
  });
});
