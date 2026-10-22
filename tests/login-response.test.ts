import { runInNewContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import { loginResponse } from "../src/lib/login-response";

const requestId = "r".repeat(43);

describe("Direct popup login response", () => {
  it("delivers the JWT only to the configured origin and clears the callback URL", async () => {
    const response = loginResponse("https://app.example", requestId, "signed.jwt.value");
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    const html = await response.text();
    const script = html.match(/<script nonce="([^"]+)">([\s\S]*?)<\/script>/)!;
    expect(response.headers.get("content-security-policy")).toContain(`script-src 'nonce-${script[1]}'`);
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    const window = {
      history: { replaceState: vi.fn() },
      opener: { postMessage: vi.fn() },
      close: vi.fn(),
    };
    runInNewContext(script[2], { window });
    expect(window.opener.postMessage).toHaveBeenCalledWith({
      type: "spid-login", requestId, token: "signed.jwt.value",
    }, "https://app.example");
    expect(window.history.replaceState).toHaveBeenCalledWith(null, "", "/auth/complete");
    expect(window.close).toHaveBeenCalledOnce();
  });

  it("escapes script-breaking payloads without changing the delivered value", async () => {
    const token = "</script><script>alert('x')</script>&\u2028\u2029";
    const html = await loginResponse("https://app.example", requestId, token).text();
    expect(html.match(/<script /g)).toHaveLength(1);
    const script = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)![1];
    const postMessage = vi.fn();
    runInNewContext(script, {
      window: { history: { replaceState: vi.fn() }, opener: { postMessage }, close: vi.fn() },
    });
    expect(postMessage).toHaveBeenCalledWith({
      type: "spid-login", requestId, token,
    }, "https://app.example");
  });

  it("uses a fresh CSP nonce and rejects invalid request IDs", () => {
    expect(loginResponse("https://app.example", requestId, "jwt").headers.get("content-security-policy"))
      .not.toBe(loginResponse("https://app.example", requestId, "jwt").headers.get("content-security-policy"));
    expect(() => loginResponse("https://app.example", "invalid", "jwt")).toThrow("request ID");
  });
});
