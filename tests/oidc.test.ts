import { afterEach, describe, expect, it, vi } from "vitest";
import { achievedLevel, readOidcSettings, satisfiesLevel } from "../src/lib/oidc";
import { createAuthConfig } from "../src/auth.config";

afterEach(() => vi.unstubAllEnvs());

function configure() {
  vi.stubEnv("BETTER_AUTH_URL", "http://localhost:3000");
  vi.stubEnv("BETTER_AUTH_SECRET", "test-only-secret-with-at-least-32-characters");
  vi.stubEnv("OIDC_ISSUER", "https://idp.example.test");
  vi.stubEnv("OIDC_CLIENT_ID", "test-client");
  vi.stubEnv("OIDC_CLIENT_SECRET", "test-only-secret");
}

describe("SPID OIDC configuration", () => {
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
