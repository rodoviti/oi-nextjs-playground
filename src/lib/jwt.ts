import { randomUUID } from "node:crypto";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { createLocalJWKSet, errors, jwtVerify } from "jose";
import { getDatabase } from "./database";
import { getRedis } from "./redis";
import { sessionFields, userFields } from "./auth-schema";
import { projectSession, SESSION_TTL, type AppSession, type PersistedSession } from "./session";

export function jwtPlugin() {
  return jwt({
    jwks: { keyPairConfig: { alg: "RS256" } },
    jwt: { expirationTime: "1h" },
    disableSettingJwtHeader: true,
  });
}

function tokenAuth() {
  return betterAuth({
    database: getDatabase(),
    user: { additionalFields: userFields },
    session: { additionalFields: sessionFields },
    plugins: [jwtPlugin()],
  });
}

export async function tokenAuthContext() {
  return tokenAuth().$context;
}

export async function publicJwks() {
  return tokenAuth().api.getJwks();
}

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function appOrigin() {
  const context = await tokenAuth().$context;
  if (!context.baseURL) {
    throw new Error("Configure BETTER_AUTH_URL before using bearer authentication");
  }
  return new URL(context.baseURL).origin;
}

export async function issueToken(sessionId: string) {
  const result = await getDatabase().query<PersistedSession & { name: string; email: string }>(
    `SELECT s.*, u.name, u.email FROM "session" s JOIN "user" u ON u.id = s."userId"
     WHERE s.id = $1`, [sessionId],
  );
  const session = result.rows[0];
  if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
    throw new HttpError(401, "Sessione non valida o scaduta");
  }
  if (await (await getRedis()).exists(`revoked:${session.id}`)) {
    throw new HttpError(401, "Sessione revocata");
  }
  const projection = projectSession(session, session);
  const { token } = await tokenAuth().api.signJWT({
    body: {
      payload: {
        sub: session.subject,
        sid: session.id,
        jti: randomUUID(),
        iat: Math.floor(session.createdAt.getTime() / 1000),
        exp: Math.floor(session.expiresAt.getTime() / 1000),
        session: projection,
      },
    },
  });
  return { token, session: projection };
}

export async function authenticate(request: Request, checkRevocation = true) {
  const authorization = request.headers.get("authorization");
  const match = authorization?.match(/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i);
  if (!match) throw new HttpError(401, "Bearer token richiesto");
  const auth = tokenAuth();
  const origin = await appOrigin();
  const jwks = await auth.api.getJwks();
  let payload;
  try {
    ({ payload } = await jwtVerify(match[1], createLocalJWKSet(jwks), {
      algorithms: ["RS256"],
      issuer: origin,
      audience: origin,
      clockTolerance: 0,
      requiredClaims: ["sub", "sid", "jti", "iat", "exp"],
    }));
  } catch (error) {
    if (error instanceof errors.JOSEError) throw new HttpError(401, "JWT non valido o scaduto");
    throw error;
  }
  if (
    typeof payload.sid !== "string" || typeof payload.jti !== "string" ||
    typeof payload.iat !== "number" || typeof payload.exp !== "number" ||
    payload.exp - payload.iat !== SESSION_TTL || payload.iat > Math.floor(Date.now() / 1000)
  ) throw new HttpError(401, "Claim JWT non validi");
  const session = readSessionClaim(payload.session);
  if (
    session.id !== payload.sid || session.user.id !== payload.sub ||
    Date.parse(session.startedAt) !== payload.iat * 1000 ||
    Date.parse(session.expires) !== payload.exp * 1000
  ) throw new HttpError(401, "Sessione JWT non valida");
  if (checkRevocation && await (await getRedis()).exists(`revoked:${payload.sid}`)) {
    throw new HttpError(401, "Sessione revocata");
  }
  return { session, expiresAt: payload.exp };
}

function readSessionClaim(value: unknown): AppSession {
  if (
    !value || typeof value !== "object" ||
    !("id" in value) || typeof value.id !== "string" ||
    !("level" in value) ||
    !("provider" in value) || typeof value.provider !== "string" ||
    !("startedAt" in value) || typeof value.startedAt !== "string" ||
    !("expires" in value) || typeof value.expires !== "string" ||
    !("user" in value) || !value.user || typeof value.user !== "object" ||
    !("id" in value.user) || typeof value.user.id !== "string" ||
    !("name" in value.user) || typeof value.user.name !== "string" ||
    !("email" in value.user) || typeof value.user.email !== "string" ||
    ("authTime" in value && typeof value.authTime !== "number")
  ) throw new HttpError(401, "Metadati JWT non validi");
  if (value.provider === "magic-link") {
    if (value.level !== null || "acr" in value || "authTime" in value) {
      throw new HttpError(401, "Metadati magic link non validi");
    }
  } else if (
    (value.level !== "L2" && value.level !== "L3") ||
    !("acr" in value) || typeof value.acr !== "string"
  ) throw new HttpError(401, "Metadati SPID non validi");
  return {
    id: value.id,
    user: { id: value.user.id, name: value.user.name, email: value.user.email },
    level: value.level === "L2" || value.level === "L3" ? value.level : null,
    ...("acr" in value && typeof value.acr === "string" ? { acr: value.acr } : {}),
    provider: value.provider,
    startedAt: value.startedAt,
    expires: value.expires,
    ...("authTime" in value && typeof value.authTime === "number" ? { authTime: value.authTime } : {}),
  };
}

export async function revokeSession(sessionId: string, expiresAt: number) {
  const remaining = expiresAt - Math.floor(Date.now() / 1000);
  if (remaining <= 0) throw new HttpError(401, "Sessione scaduta");
  await (await getRedis()).set(`revoked:${sessionId}`, "1", { EXAT: expiresAt });
  await getDatabase().query(
    'UPDATE "session" SET "revokedAt" = COALESCE("revokedAt", now()) WHERE id = $1',
    [sessionId],
  );
}

export async function apiResponse(action: () => Promise<Response>): Promise<Response> {
  try {
    const response = await action();
    response.headers.set("Cache-Control", "no-store");
    response.headers.set("Referrer-Policy", "no-referrer");
    return response;
  } catch (error) {
    if (!(error instanceof HttpError)) console.error("[api] Authentication infrastructure failed", error);
    return Response.json(
      { error: error instanceof HttpError ? error.message : "Servizio di autenticazione non disponibile" },
      {
        status: error instanceof HttpError ? error.status : 503,
        headers: {
          "Cache-Control": "no-store",
          ...(error instanceof HttpError && error.status === 401 ? { "WWW-Authenticate": "Bearer" } : {}),
        },
      },
    );
  }
}

export async function readBody(request: Request): Promise<Record<string, unknown>> {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    throw new HttpError(415, "Content-Type application/json richiesto");
  }
  try {
    const value: unknown = await request.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "JSON non valido");
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof SyntaxError) throw new HttpError(400, "JSON non valido");
    throw error;
  }
}

export async function requireBrowserOrigin(request: Request) {
  if (request.headers.get("origin") !== await appOrigin()) {
    throw new HttpError(403, "Origine non consentita");
  }
}
