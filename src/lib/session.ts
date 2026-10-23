import type { SpidLevel } from "./oidc";

export const SESSION_TTL = 60 * 60;

export type LoginIdentity = {
  subject: string;
  issuer: string;
  level: SpidLevel | null;
  acr?: string | null;
  provider: string;
  authTime?: number;
};

export type AppSession = {
  id: string;
  user: { id: string; name: string; email: string };
  level: SpidLevel | null;
  acr?: string;
  provider: string;
  startedAt: string;
  expires: string;
  authTime?: number;
};

export type PersistedSession = LoginIdentity & {
  id: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
};

export function projectSession(
  session: PersistedSession,
  user: { name: string; email: string },
): AppSession {
  const start = session.createdAt.getTime();
  const deadline = session.expiresAt.getTime();
  if (!Number.isFinite(start) || deadline - start !== SESSION_TTL * 1000) {
    throw new Error("Invalid absolute session lifetime");
  }
  if (session.provider === "magic-link") {
    if (session.level !== null || session.acr != null || session.authTime != null) {
      throw new Error("Magic-link session must not assert SPID authentication");
    }
  } else if ((session.level !== "L2" && session.level !== "L3") || typeof session.acr !== "string") {
    throw new Error("Session has an unsupported SPID level");
  }
  return {
    id: session.id,
    user: { id: session.subject, name: user.name, email: user.email },
    level: session.level,
    ...(typeof session.acr === "string" ? { acr: session.acr } : {}),
    provider: session.provider,
    startedAt: session.createdAt.toISOString(),
    expires: session.expiresAt.toISOString(),
    ...(typeof session.authTime === "number" ? { authTime: session.authTime } : {}),
  };
}
