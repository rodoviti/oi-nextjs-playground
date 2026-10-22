import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe("Next.js development origins", () => {
  it("allows only the configured tunnel hostname, without scheme or path", async () => {
    vi.stubEnv("BETTER_AUTH_URL", "https://bunny-controller-causes-former.trycloudflare.com");
    const { default: config } = await import("../next.config");

    expect(config.allowedDevOrigins).toEqual([
      "bunny-controller-causes-former.trycloudflare.com",
    ]);
  });

  it("supports localhost with a custom port", async () => {
    vi.stubEnv("BETTER_AUTH_URL", "http://localhost:3000");
    const { default: config } = await import("../next.config");

    expect(config.allowedDevOrigins).toEqual(["localhost"]);
  });

  it("adds no development origins when BETTER_AUTH_URL is unset", async () => {
    vi.stubEnv("BETTER_AUTH_URL", undefined);
    const { default: config } = await import("../next.config");

    expect(config.allowedDevOrigins).toEqual([]);
  });

  it("fails explicitly for an invalid BETTER_AUTH_URL", async () => {
    vi.stubEnv("BETTER_AUTH_URL", "not-a-url");

    await expect(import("../next.config")).rejects.toThrow("Invalid URL");
  });
});
