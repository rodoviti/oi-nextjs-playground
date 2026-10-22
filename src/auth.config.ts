import type { BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { nextCookies } from "better-auth/next-js";
import { customSession, genericOAuth } from "better-auth/plugins";
import { decodeJwt } from "jose";
import {
  achievedLevel,
  readOidcSettings,
  satisfiesLevel,
  SPID_LEVELS,
} from "./lib/oidc";
import { projectSession, SESSION_TTL } from "./lib/session";

export function createAuthConfig() {
  const settings = readOidcSettings();

  const options = {
    session: {
      expiresIn: SESSION_TTL,
      disableSessionRefresh: true,
      cookieCache: {
        enabled: true,
        strategy: "jwe",
        maxAge: SESSION_TTL,
        refreshCache: false,
      },
    },
    account: {
      storeStateStrategy: "cookie",
      storeAccountCookie: false,
      accountLinking: { enabled: false },
    },
    user: {
      additionalFields: {
        subject: { type: "string", required: true },
        level: { type: "string", required: true },
        acr: { type: "string", required: true },
        provider: { type: "string", required: true },
        authTime: { type: "number", required: false },
      },
      validateUserInfo: ({ source }) => {
        const provider = source.oauth?.providerId;
        const profile = source.oauth?.profile;
        const requested = provider === "spid-l3" ? "L3" : "L2";
        const actual = achievedLevel(profile?.acr, settings);
        if (!satisfiesLevel(actual, requested)) {
          console.warn(
            "[auth] ID token acr does not satisfy the requested SPID level",
            {
              provider,
              requested,
              actual,
            },
          );
          return { error: "InsufficientAcr" };
        }
      },
    },
    onAPIError: { errorURL: "/" },
    databaseHooks: {
      session: {
        create: {
          before: async () => {
            const startedAt = Math.floor(Date.now() / 1000) * 1000;
            return {
              data: {
                createdAt: new Date(startedAt),
                updatedAt: new Date(startedAt),
                expiresAt: new Date(startedAt + SESSION_TTL * 1000),
              },
            };
          },
        },
      },
    },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        // This PoC exposes login, local logout and read-only session access only.
        if (
          ![
            "/sign-in/social",
            "/sign-out",
            "/get-session",
            "/callback/:id",
          ].includes(ctx.path)
        ) {
          throw new APIError("NOT_FOUND", {
            message: "Unsupported authentication endpoint",
          });
        }
        if (ctx.path === "/sign-in/social" && ctx.body?.idToken) {
          throw new APIError("BAD_REQUEST", {
            message: "Use the OIDC authorization code flow",
          });
        }
      }),
      after: createAuthMiddleware(async (ctx) => {
        const session = ctx.context.session?.session;
        // Better Auth's cookie decoder has clock tolerance; enforce the exact deadline.
        if (
          ctx.path === "/get-session" &&
          session &&
          session.expiresAt.getTime() <= Date.now()
        ) {
          return ctx.json(null);
        }
      }),
    },
  } satisfies BetterAuthOptions;

  return {
    ...options,
    plugins: [
      genericOAuth({
        config: SPID_LEVELS.map((level) => ({
          providerId: `spid-${level.toLowerCase()}`,
          discoveryUrl: `${settings.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
          requireIdTokenVerification: true,
          clientId: settings.clientId,
          clientSecret: settings.clientSecret,
          tokenEndpointAuth: { method: "client_secret_basic" as const },
          scopes: ["openid"],
          pkce: true,
          prompt: "login" as const,
          disableProviderLogout: true,
          authorizationUrlParams: {
            idp: "https://idp.uat.io.oneid.pagopa.it",
            acr_values: settings.acr[level],
          },
          getUserInfo: async (tokens) => {
            // Generic OAuth verifies the signature, audience and nonce before this hook.
            if (!tokens.idToken) {
              console.warn("[auth] OIDC response has no ID token");
              return null;
            }
            const claims = decodeJwt(tokens.idToken);
            if (claims.iss !== settings.issuer || !claims.sub) {
              console.warn(
                "[auth] ID token has an unexpected issuer or missing subject",
              );
              return null;
            }
            return {
              ...claims,
              name: typeof claims.name === "string" ? claims.name : "",
              email:
                typeof claims.email === "string" ? claims.email : undefined,
              emailVerified: claims.email_verified === true,
            };
          },
          mapProfileToUser: (profile) => ({
            subject: profile.sub,
            level: achievedLevel(profile.acr, settings),
            acr: profile.acr,
            provider: `spid-${level.toLowerCase()}`,
            ...(typeof profile.auth_time === "number"
              ? { authTime: profile.auth_time }
              : {}),
          }),
        })),
      }),
      customSession(
        async ({ user, session }) => projectSession({ user, session }),
        options,
      ),
      nextCookies(),
    ],
  };
}
