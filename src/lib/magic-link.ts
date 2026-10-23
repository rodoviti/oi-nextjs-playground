import { createHash, randomBytes } from "node:crypto";
import { getDatabase } from "./database";
import { getRedis } from "./redis";
import { authenticate, HttpError, issueToken, tokenAuthContext } from "./jwt";
import { SESSION_TTL, type PersistedSession } from "./session";

export const MAGIC_LINK_TTL = 86400;
const PURPOSE = "magic-link";

function identifier(token: string) {
  return `${PURPOSE}:${createHash("sha256").update(token).digest("hex")}`;
}

async function sourceSession(id: string) {
  const result = await getDatabase().query<PersistedSession>(
    'SELECT * FROM "session" WHERE id = $1', [id],
  );
  const source = result.rows[0];
  if (!source || source.revokedAt || await (await getRedis()).exists(`revoked:${id}`)) {
    throw new HttpError(401, "Sessione sorgente non valida o revocata");
  }
  return source;
}

export async function generateMagicLink(request: Request) {
  const { session } = await authenticate(request);
  await sourceSession(session.id);
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Math.floor(Date.now() / 1000) * 1000 + MAGIC_LINK_TTL * 1000);
  const context = await tokenAuthContext();
  const verification = await context.internalAdapter.createVerificationValue({
    identifier: identifier(token),
    value: JSON.stringify({ sessionId: session.id, subject: session.user.id }),
    expiresAt,
  });
  if (!verification) throw new Error("Unable to store magic-link verification");
  return { token, expiresAt: expiresAt.toISOString() };
}

export async function redeemMagicLink(token: unknown) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    throw new HttpError(400, "Token magic link richiesto o formato non valido");
  }
  const context = await tokenAuthContext();
  const verification = await context.internalAdapter.consumeVerificationValue(identifier(token));
  // Better Auth accepts expiresAt === now; enforce the API's exact expiry boundary.
  if (!verification || verification.expiresAt.getTime() <= Date.now()) {
    throw new HttpError(401, "Magic link gia' utilizzato, scaduto o non valido");
  }
  const payload: unknown = JSON.parse(verification.value);
  if (
    !payload || typeof payload !== "object" ||
    !("sessionId" in payload) || typeof payload.sessionId !== "string" ||
    !("subject" in payload) || typeof payload.subject !== "string"
  ) throw new Error("Invalid stored magic-link verification");
  const source = await sourceSession(payload.sessionId);
  if (source.subject !== payload.subject) throw new HttpError(401, "Identita' magic link non valida");

  const startedAt = Math.floor(Date.now() / 1000) * 1000;
  const session = await context.internalAdapter.createSession(source.userId, false, {
    subject: source.subject, issuer: source.issuer,
    level: null, acr: null, authTime: null, provider: PURPOSE,
    createdAt: new Date(startedAt), updatedAt: new Date(startedAt),
    expiresAt: new Date(startedAt + SESSION_TTL * 1000),
  }, true);
  if (!session) throw new Error("Unable to create magic-link session");
  return issueToken(session.id);
}
