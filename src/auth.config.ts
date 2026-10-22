import type { BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { genericOAuth } from "better-auth/plugins";
import { decodeJwt } from "jose";
import {
  achievedLevel,
  readOidcSettings,
  satisfiesLevel,
  SPID_LEVELS,
} from "./lib/oidc";
import { getDatabase } from "./lib/database";
import { issueToken, jwtPlugin } from "./lib/jwt";
import { LOGIN_REQUEST_PATTERN, loginResponse } from "./lib/login-response";
import { sessionFields, userFields } from "./lib/auth-schema";
import { SESSION_TTL, type LoginIdentity } from "./lib/session";

export function createAuthConfig() {
  const settings = readOidcSettings();
  let identity: LoginIdentity | undefined;

  const options = {
    database: getDatabase(),
    session: {
      expiresIn: SESSION_TTL,
      disableSessionRefresh: true,
      cookieCache: { enabled: false },
      additionalFields: sessionFields,
    },
    account: {
      storeStateStrategy: "cookie",
      storeAccountCookie: false,
      updateAccountOnSignIn: false,
      accountLinking: {
        enabled: true,
        trustedProviders: ["spid-l2", "spid-l3"],
        requireLocalEmailVerified: false,
      },
    },
    user: {
      additionalFields: userFields,
      validateUserInfo: async ({ user, source }) => {
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
        if (!actual || !provider || typeof profile?.sub !== "string" || profile.iss !== settings.issuer) {
          return { error: "InvalidIdentity" };
        }
        if (source.action !== "create-user") {
          const existing = await getDatabase().query<{ subject: string; issuer: string }>(
            'SELECT subject, issuer FROM "user" WHERE id = $1', [user.id],
          );
          const binding = existing.rows[0];
          if (binding?.subject !== profile.sub || binding?.issuer !== settings.issuer) {
            console.warn("[auth] Refusing account binding to a different OIDC identity", {
              action: source.action,
              provider,
              userFound: !!binding,
              subjectMatches: binding?.subject === profile.sub,
              issuerMatches: binding?.issuer === settings.issuer,
            });
            return { error: "IdentityMismatch" };
          }
        }
        identity = {
          subject: profile.sub,
          issuer: settings.issuer,
          level: actual,
          acr: settings.acr[actual],
          provider,
          ...(typeof profile.auth_time === "number" ? { authTime: profile.auth_time } : {}),
        };
      },
    },
    onAPIError: { errorURL: "/auth/complete" },
    databaseHooks: {
      account: {
        create: {
          before: async () => ({
            data: {
              accessToken: null,
              refreshToken: null,
              idToken: null,
              accessTokenExpiresAt: null,
              refreshTokenExpiresAt: null,
            },
          }),
        },
      },
      session: {
        create: {
          before: async () => {
            if (!identity) throw new Error("Session creation requires verified OIDC identity");
            const startedAt = Math.floor(Date.now() / 1000) * 1000;
            return {
              data: {
                ...identity,
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
        // Public auth routes are further restricted by the Next.js route handler.
        if (ctx.path && (
          ![
            "/sign-in/social",
            "/callback/:id",
            "/jwks",
          ].includes(ctx.path)
        )) {
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
        if (ctx.path === "/callback/:id" && ctx.context.newSession) {
          const location = ctx.context.responseHeaders?.get("location");
          if (!location) throw new Error("Missing OIDC callback destination");
          const target = new URL(location, ctx.context.baseURL);
          const requestId = target.searchParams.get("requestId");
          if (
            target.origin !== new URL(ctx.context.baseURL).origin ||
            target.pathname !== "/auth/complete" || !requestId || !LOGIN_REQUEST_PATTERN.test(requestId)
          ) {
            throw new Error("Invalid OIDC login destination");
          }
          const { token } = await issueToken(ctx.context.newSession.session.id);
          ctx.context.responseHeaders?.delete("location");
          return loginResponse(target.origin, requestId, token);
        }
      }),
    },
  } satisfies BetterAuthOptions;

  return {
    ...options,
    plugins: [
      jwtPlugin(),
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
            issuer: settings.issuer,
          }),
        })),
      }),
    ],
  };
}
