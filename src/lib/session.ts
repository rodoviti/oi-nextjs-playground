import type { SpidLevel } from "./oidc";

export const SESSION_TTL = 60 * 60;

export type AppSession = {
  user: { id: string; name: string; email: string };
  level: SpidLevel;
  acr: string;
  provider: string;
  startedAt: string;
  expires: string;
  authTime?: number;
};

type SessionData = {
  user: {
    name: string;
    email: string;
    subject: string;
    level: string;
    acr: string;
    provider: string;
    authTime?: number | null;
  };
  session: { createdAt: Date; expiresAt: Date };
};

export function projectSession({ user, session }: SessionData): AppSession {
  const start = session.createdAt.getTime();
  const deadline = session.expiresAt.getTime();
  if (!Number.isFinite(start) || deadline - start !== SESSION_TTL * 1000) {
    throw new Error("Invalid absolute session lifetime");
  }
  if (user.level !== "L2" && user.level !== "L3") {
    throw new Error("Session has an unsupported SPID level");
  }
  return {
    user: { id: user.subject, name: user.name, email: user.email },
    level: user.level,
    acr: user.acr,
    provider: user.provider,
    startedAt: session.createdAt.toISOString(),
    expires: session.expiresAt.toISOString(),
    ...(typeof user.authTime === "number" ? { authTime: user.authTime } : {}),
  };
}
