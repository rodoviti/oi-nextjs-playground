import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  workers: 1,
  use: { baseURL: "http://localhost:3100" },
  webServer: [
    {
      command: "npx tsx tests/e2e/mock-idp.ts",
      url: "http://localhost:4100/.well-known/openid-configuration",
      reuseExistingServer: false,
    },
    {
      command: "npm run start -- --port 3100",
      url: "http://localhost:3100",
      reuseExistingServer: false,
      env: {
        AUTH_URL: "http://localhost:3100",
        AUTH_SECRET: "e2e-only-secret-not-for-production-32-characters",
        OIDC_ISSUER: "http://localhost:4100",
        OIDC_CLIENT_ID: "test-client",
        OIDC_CLIENT_SECRET: "test-secret",
        OIDC_ACR_L2: "https://www.spid.gov.it/SpidL2",
        OIDC_ACR_L3: "https://www.spid.gov.it/SpidL3",
      },
    },
  ],
});
