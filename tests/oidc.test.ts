import { afterEach, describe, expect, it, vi } from "vitest";
import { achievedLevel, loginErrorMessage, readOidcSettings, satisfiesLevel } from "../src/lib/oidc";
import { createAuthConfig } from "../src/auth.config";

const query = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/database", () => ({ getDatabase: () => ({ query }) }));

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  query.mockReset();
});

function configure() {
  vi.stubEnv("BETTER_AUTH_URL", "http://localhost:3000");
  vi.stubEnv("BETTER_AUTH_SECRET", "test-only-secret-with-at-least-32-characters");
  vi.stubEnv("OIDC_ISSUER", "https://idp.example.test");
  vi.stubEnv("OIDC_CLIENT_ID", "test-client");
  vi.stubEnv("OIDC_CLIENT_SECRET", "test-only-secret");
}

describe("SPID OIDC configuration", () => {
  it("explains identity binding rejection without hiding other safe error codes", () => {
    expect(loginErrorMessage("IdentityMismatch")).toContain("Il collegamento e' stato rifiutato");
    expect(loginErrorMessage("InsufficientAcr")).toContain("livello");
    expect(loginErrorMessage("InvalidIdentity")).toContain("non valida");
    expect(loginErrorMessage("state_security_mismatch")).toContain("state_security_mismatch");
    expect(loginErrorMessage("<script>private details</script>")).not.toContain("private details");
    expect(loginErrorMessage(undefined)).toContain("log del server");
  });

  it.each(["sign-in", "link-account"] as const)("allows %s only for the same persisted issuer and subject", async (action) => {
    configure();
    const validate = createAuthConfig().user.validateUserInfo;
    const user = {
      id: "internal-user", name: "Utente", email: "user@example.test",
      emailVerified: true, createdAt: new Date(), updatedAt: new Date(),
    };
    const source = {
      action, method: "oauth" as const,
      oauth: {
        providerId: "spid-l2",
        profile: {
          sub: "same-subject", iss: "https://idp.example.test",
          acr: "https://www.spid.gov.it/SpidL2",
        },
      },
    };
    query.mockResolvedValue({ rows: [{ subject: "same-subject", issuer: "https://idp.example.test" }] });
    expect(await validate({ user, source })).toBeUndefined();
    expect(query).toHaveBeenCalledWith(expect.any(String), ["internal-user"]);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    query.mockResolvedValue({ rows: [{ subject: "different-subject", issuer: "https://idp.example.test" }] });
    expect(await validate({ user, source })).toEqual({ error: "IdentityMismatch" });
    expect(warn).toHaveBeenLastCalledWith(expect.any(String), {
      action, provider: "spid-l2", userFound: true, subjectMatches: false, issuerMatches: true,
    });
    query.mockResolvedValue({ rows: [{ subject: "same-subject", issuer: "https://other.example.test" }] });
    expect(await validate({ user, source })).toEqual({ error: "IdentityMismatch" });
    query.mockResolvedValue({ rows: [] });
    expect(await validate({ user, source })).toEqual({ error: "IdentityMismatch" });
    expect(warn).toHaveBeenLastCalledWith(expect.any(String), {
      action, provider: "spid-l2", userFound: false, subjectMatches: false, issuerMatches: false,
    });
  });
  it("configures distinct L2/L3 flows with forced login, PKCE, state and nonce", () => {
    configure();
    const providers = createAuthConfig().plugins.find((plugin) => plugin.id === "generic-oauth")!.options.config;
    expect(providers).toMatchObject([
      {
        providerId: "spid-l2",
        pkce: true,
        requireIdTokenVerification: true,
        prompt: "login",
        tokenEndpointAuth: { method: "client_secret_basic" },
        disableProviderLogout: true,
        authorizationUrlParams: { acr_values: "https://www.spid.gov.it/SpidL2" },
      },
      {
        providerId: "spid-l3",
        pkce: true,
        requireIdTokenVerification: true,
        prompt: "login",
        disableProviderLogout: true,
        authorizationUrlParams: { acr_values: "https://www.spid.gov.it/SpidL3" },
      },
    ]);
  });

  it("leaves base URL resolution to Better Auth", () => {
    configure();
    expect(createAuthConfig()).not.toHaveProperty("baseURL");
  });

  it("leaves secret resolution to Better Auth", () => {
    configure();
    expect(createAuthConfig()).not.toHaveProperty("secret");
  });

  it("accepts only a known level meeting the requested minimum", () => {
    configure();
    const settings = readOidcSettings();
    expect(achievedLevel(settings.acr.L3, settings)).toBe("L3");
    expect(achievedLevel(undefined, settings)).toBeNull();
    expect(achievedLevel("unknown", settings)).toBeNull();
    expect(satisfiesLevel("L3", "L2")).toBe(true);
    expect(satisfiesLevel("L3", "L3")).toBe(true);
    expect(satisfiesLevel("L2", "L2")).toBe(true);
    expect(satisfiesLevel("L2", "L3")).toBe(false);
    expect(satisfiesLevel(null, "L2")).toBe(false);
  });

  it("supports IdP-specific acr values and fails on missing or ambiguous settings", () => {
    configure();
    vi.stubEnv("OIDC_ACR_L2", "urn:example:l2");
    vi.stubEnv("OIDC_ACR_L3", "urn:example:l3");
    expect(achievedLevel("urn:example:l3", readOidcSettings())).toBe("L3");
    vi.stubEnv("OIDC_ACR_L3", "urn:example:l2");
    expect(readOidcSettings).toThrow("distinct");
    vi.stubEnv("OIDC_CLIENT_SECRET", "");
    vi.stubEnv("OIDC_ACR_L3", "urn:example:l3");
    expect(readOidcSettings).toThrow("OIDC_CLIENT_SECRET");
  });
});
