import { describe, expect, it } from "vitest";
import { projectSession, SESSION_TTL, type PersistedSession } from "../src/lib/session";
import { withoutSessionCookies } from "../src/lib/auth-response";

function data(): PersistedSession {
  return {
    id: "session-id",
    userId: "internal-user",
    subject: "oidc-user",
    issuer: "https://idp.example.test",
    level: "L2",
    acr: "https://www.spid.gov.it/SpidL2",
    provider: "spid-l2",
    createdAt: new Date(1_800_000_000_000),
    expiresAt: new Date((1_800_000_000 + SESSION_TTL) * 1000),
    revokedAt: null,
  };
}

describe("Persistent session projection", () => {
  it("projects immutable per-session SPID metadata without internal credentials", () => {
    const session = projectSession(data(), { name: "Utente", email: "demo@example.test" });
    expect(session).toMatchObject({ id: "session-id", user: { id: "oidc-user" }, level: "L2" });
    expect(Date.parse(session.expires) - Date.parse(session.startedAt)).toBe(3_600_000);
    expect(JSON.stringify(session)).not.toMatch(/token|internal-user|revokedAt/);
  });

  it("rejects invalid or sliding lifetimes", () => {
    const session = data();
    session.expiresAt = new Date(session.expiresAt.getTime() + 1000);
    expect(() => projectSession(session, { name: "", email: "" })).toThrow("lifetime");
    session.createdAt = new Date(NaN);
    expect(() => projectSession(session, { name: "", email: "" })).toThrow("lifetime");
  });

  it("does not expose authTime when absent", () => {
    expect(projectSession(data(), { name: "", email: "" })).not.toHaveProperty("authTime");
    expect(projectSession({ ...data(), authTime: 123 }, { name: "", email: "" }).authTime).toBe(123);
  });
});

describe("Bearer-only auth responses", () => {
  it("strips all session/token cookie chunks but preserves temporary OIDC state", () => {
    const headers = new Headers({ Location: "/auth/complete?code=opaque" });
    for (const cookie of [
      "better-auth.session_token=secret; HttpOnly",
      "__Secure-better-auth.session_data.0=secret; Secure",
      "better-auth.account_data=secret",
      "better-auth.dont_remember=1",
      "better-auth.oauth_state=temporary; HttpOnly",
    ]) headers.append("Set-Cookie", cookie);
    const response = withoutSessionCookies(new Response(null, { status: 302, headers }));
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toContain("code=opaque");
    expect(response.headers.getSetCookie()).toEqual(["better-auth.oauth_state=temporary; HttpOnly"]);
  });
});
