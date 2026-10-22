import { afterEach, describe, expect, it, vi } from "vitest";
import { betterAuth } from "better-auth";
import { makeSignature, symmetricDecodeJWT, symmetricEncodeJWT } from "better-auth/crypto";
import { decodeProtectedHeader } from "jose";
import { createAuthConfig } from "../src/auth.config";
import { projectSession, SESSION_TTL } from "../src/lib/session";

const secret = "test-only-secret-with-at-least-32-characters";
const start = 1_800_000_000;
const salt = "better-auth-session";

function configure(url = "http://localhost:3000") {
  vi.stubEnv("BETTER_AUTH_URL", url);
  vi.stubEnv("BETTER_AUTH_SECRET", secret);
  vi.stubEnv("OIDC_ISSUER", "https://idp.example.test");
  vi.stubEnv("OIDC_CLIENT_ID", "test-client");
  vi.stubEnv("OIDC_CLIENT_SECRET", "test-secret");
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(start * 1000);
  const config = createAuthConfig();
  return betterAuth({
    ...config,
    plugins: config.plugins.filter((plugin) => plugin.id !== "generic-oauth"),
  });
}

function data() {
  const createdAt = new Date(start * 1000);
  return {
    user: {
      id: "internal-user",
      subject: "test-user",
      name: "Utente Demo",
      email: "demo@example.test",
      emailVerified: false,
      level: "L2",
      acr: "https://www.spid.gov.it/SpidL2",
      provider: "spid-l2",
      createdAt,
      updatedAt: createdAt,
    },
    session: {
      id: "test-session",
      token: "opaque-session-token",
      userId: "internal-user",
      createdAt,
      updatedAt: createdAt,
      expiresAt: new Date((start + SESSION_TTL) * 1000),
    },
    updatedAt: start * 1000,
    version: "1",
  };
}

async function cookies(encryptionSecret = secret) {
  const jwe = await symmetricEncodeJWT(data(), encryptionSecret, salt, SESSION_TTL);
  const token = data().session.token;
  const signature = await makeSignature(token, secret);
  return {
    jwe,
    header: `better-auth.session_token=${encodeURIComponent(`${token}.${signature}`)}; better-auth.session_data=${jwe}`,
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

describe("Better Auth absolute JWE session", () => {
  it("resolves BETTER_AUTH_SECRET without an explicit secret option", async () => {
    const auth = configure();
    expect(auth.options).not.toHaveProperty("secret");
    expect((await auth.$context).secret).toBe(secret);
  });

  it.each([
    ["http://localhost:3000", "better-auth.session_data", false],
    ["https://app.example.test", "__Secure-better-auth.session_data", true],
  ])("resolves %s from BETTER_AUTH_URL without an explicit baseURL", async (url, cookieName, secure) => {
    const auth = configure(url);
    expect(auth.options).not.toHaveProperty("baseURL");
    const context = await auth.$context;
    expect(context.baseURL).toBe(`${url}/api/auth`);
    expect(context.trustedOrigins).toContain(url);
    expect(context.authCookies.sessionData.name).toBe(cookieName);
    expect(context.authCookies.sessionData.attributes).toMatchObject({
      secure, httpOnly: true, sameSite: "lax",
    });
  });

  it("encrypts metadata and exposes only the minimal session projection", async () => {
    const auth = configure();
    const { jwe, header } = await cookies();
    expect(jwe.split(".")).toHaveLength(5);
    expect(decodeProtectedHeader(jwe)).toMatchObject({ alg: "dir", enc: "A256CBC-HS512" });
    expect(await symmetricDecodeJWT(jwe, secret, salt)).toMatchObject({ exp: start + 3600 });
    const session = await auth.api.getSession({ headers: new Headers({ cookie: header }) });
    expect(session).toEqual(projectSession(data()));
    expect(session?.user.id).toBe("test-user");
    expect(JSON.stringify(session)).not.toMatch(/token|internal-user/);
  });

  it("does not extend the deadline on reads and rejects the exact expiry boundary", async () => {
    const auth = configure();
    const { header } = await cookies();
    for (const elapsed of [0, 1800, 3599]) {
      vi.setSystemTime((start + elapsed) * 1000);
      const response = await auth.handler(new Request("http://localhost:3000/api/auth/get-session", {
        headers: { cookie: header },
      }));
      expect(response.status).toBe(200);
      expect((await response.json()).expires).toBe(new Date((start + 3600) * 1000).toISOString());
      expect(response.headers.get("set-cookie")).toBeNull();
    }
    vi.setSystemTime((start + 3600) * 1000);
    expect(await auth.api.getSession({ headers: new Headers({ cookie: header }) })).toBeNull();
  });

  it("rejects tampering and cookies encrypted with the wrong secret", async () => {
    const auth = configure();
    const { header, jwe } = await cookies();
    const parts = jwe.split(".");
    parts[3] = `${parts[3][0] === "a" ? "b" : "a"}${parts[3].slice(1)}`;
    expect(await auth.api.getSession({
      headers: new Headers({ cookie: header.replace(jwe, parts.join(".")) }),
    })).toBeNull();
    const wrong = await cookies("wrong-secret");
    expect(await auth.api.getSession({ headers: new Headers({ cookie: wrong.header }) })).toBeNull();
  });

  it("rejects invalid session lifetimes and unsupported levels", async () => {
    await configure().$context;
    const invalid = data();
    invalid.session.expiresAt = new Date((start + SESSION_TTL + 1) * 1000);
    expect(() => projectSession(invalid)).toThrow("lifetime");
    const unknown = data();
    unknown.user.level = "L1";
    expect(() => projectSession(unknown)).toThrow("unsupported");
  });

  it("requires both session cookies", async () => {
    const auth = configure();
    const { jwe, header } = await cookies();
    for (const cookie of [
      `better-auth.session_data=${jwe}`,
      header.split(";")[0],
    ]) {
      expect(await auth.api.getSession({ headers: new Headers({ cookie }) })).toBeNull();
    }
  });

  it("disables renewal and token cookies and rejects client metadata updates", async () => {
    const auth = configure();
    expect(auth.options.session).toMatchObject({
      disableSessionRefresh: true,
      cookieCache: { refreshCache: false, strategy: "jwe", maxAge: SESSION_TTL },
    });
    expect(auth.options.account?.storeAccountCookie).toBe(false);
    const { header } = await cookies();
    for (const path of ["update-user", "update-session", "link-social"]) {
      const response = await auth.handler(new Request(`http://localhost:3000/api/auth/${path}`, {
        method: "POST",
        headers: { cookie: header, origin: "http://localhost:3000", "content-type": "application/json" },
        body: JSON.stringify({ level: "L3", sessionExpiresAt: start + 7200, provider: "spid-l3" }),
      }));
      expect(response.ok).toBe(false);
    }
    const directToken = await auth.handler(new Request("http://localhost:3000/api/auth/sign-in/social", {
      method: "POST",
      headers: { origin: "http://localhost:3000", "content-type": "application/json" },
      body: JSON.stringify({ provider: "spid-l3", idToken: { token: "untrusted-id-token" } }),
    }));
    expect(directToken.status).toBe(400);
    expect(await auth.api.getSession({ headers: new Headers({ cookie: header }) })).toEqual(projectSession(data()));
  });
});
