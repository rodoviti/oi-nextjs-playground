import type { NextAuthConfig } from "next-auth";
import { achievedLevel, readOidcSettings, satisfiesLevel, SPID_LEVELS } from "./lib/oidc";
import { decodeSession, encodeSession, SESSION_TTL } from "./lib/session";

export function createAuthConfig(): NextAuthConfig {
  const settings = readOidcSettings();

  return {
    pages: { signIn: "/", error: "/" },
    session: { strategy: "jwt", maxAge: SESSION_TTL },
    jwt: { maxAge: SESSION_TTL, encode: encodeSession, decode: decodeSession },
    providers: SPID_LEVELS.map((level) => ({
      id: `spid-${level.toLowerCase()}`,
      name: `SPID ${level}`,
      type: "oidc" as const,
      issuer: settings.issuer,
      clientId: settings.clientId,
      clientSecret: settings.clientSecret,
      authorization: {
        params: {
          scope: "openid profile email",
          acr_values: settings.acr[level],
          prompt: "login",
        },
      },
      checks: ["pkce", "state", "nonce"],
      profile(claims) {
        return {
          id: claims.sub,
          name: typeof claims.name === "string" ? claims.name : null,
          email: typeof claims.email === "string" ? claims.email : null,
          image: null,
        };
      },
    })),
    callbacks: {
      signIn({ account, profile }) {
        const requested = account?.provider === "spid-l3" ? "L3" : "L2";
        const actual = achievedLevel(profile?.acr, settings);
        if (!satisfiesLevel(actual, requested)) {
          console.warn("[auth] ID token acr does not satisfy the requested SPID level", {
            provider: account?.provider,
            requested,
            actual,
          });
          return "/?error=InsufficientAcr";
        }
        return true;
      },
      jwt({ token, account, profile }) {
        if (account && profile) {
          const level = achievedLevel(profile.acr, settings);
          if (!level) throw new Error("ID token has an unsupported acr");
          if (typeof profile.sub !== "string" || !profile.sub) {
            throw new Error("ID token has no subject");
          }
          const now = Math.floor(Date.now() / 1000);
          // Start a fresh session; never inherit the preceding login's deadline.
          token = {
            sub: profile.sub,
            name: token.name,
            email: token.email,
            level,
            acr: settings.acr[level],
            provider: account.provider,
            sessionStartedAt: now,
            sessionExpiresAt: now + SESSION_TTL,
            ...(typeof profile.auth_time === "number" ? { authTime: profile.auth_time } : {}),
          };
        }
        return token;
      },
      session({ session, token }) {
        if (!token.sub) throw new Error("Session token has no subject");
        return {
          ...session,
          user: { ...session.user, id: token.sub },
          level: token.level,
          acr: token.acr,
          provider: token.provider,
          startedAt: new Date(token.sessionStartedAt * 1000).toISOString(),
          expires: new Date(token.sessionExpiresAt * 1000).toISOString(),
          authTime: token.authTime,
        };
      },
    },
  };
}
