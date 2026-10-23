import { hkdfSync, randomUUID } from "node:crypto";
import { EncryptJWT, errors, jwtDecrypt } from "jose";
import { getDatabase } from "./database";
import { getRedis } from "./redis";
import { appOrigin, authenticate, HttpError, issueToken, tokenAuthContext } from "./jwt";
import { SESSION_TTL, type PersistedSession } from "./session";

export const MAGIC_LINK_TTL = 86400;
const PURPOSE = "magic-link";

async function encryptionKey() {
  const { secret } = await tokenAuthContext();
  return new Uint8Array(hkdfSync("sha256", secret, "oi-nextjs-playground", PURPOSE, 32));
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
  const origin = await appOrigin();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + MAGIC_LINK_TTL;
  const id = randomUUID();
  const jwe = await new EncryptJWT({ sid: session.id, purpose: PURPOSE })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "magic-link+jwe" })
    .setIssuer(origin).setAudience(`${origin}/api/magic-link`)
    .setSubject(session.user.id).setJti(id).setIssuedAt(now).setExpirationTime(expiresAt)
    .encrypt(await encryptionKey());
  const reserved = await (await getRedis()).set(`magic-link:${id}`, session.id, { NX: true, EXAT: expiresAt });
  if (reserved !== "OK") throw new Error("Unable to reserve magic link");
  return { jwe, expiresAt: new Date(expiresAt * 1000).toISOString() };
}

export async function redeemMagicLink(jwe: unknown) {
  if (typeof jwe !== "string" || jwe.length > 8192 || jwe.split(".").length !== 5) {
    throw new HttpError(400, "JWE richiesto o formato non valido");
  }
  const origin = await appOrigin();
  const key = await encryptionKey();
  let payload;
  try {
    const decrypted = await jwtDecrypt(jwe, key, {
      issuer: origin, audience: `${origin}/api/magic-link`,
      keyManagementAlgorithms: ["dir"], contentEncryptionAlgorithms: ["A256GCM"],
      requiredClaims: ["sub", "sid", "jti", "iat", "exp"], clockTolerance: 0,
    });
    if (decrypted.protectedHeader.typ !== "magic-link+jwe") {
      throw new HttpError(401, "Tipo JWE non valido");
    }
    payload = decrypted.payload;
  } catch (error) {
    if (error instanceof errors.JOSEError) throw new HttpError(401, "Magic link non valido o scaduto");
    throw error;
  }
  if (
    payload.purpose !== PURPOSE || typeof payload.sid !== "string" ||
    typeof payload.sub !== "string" || typeof payload.jti !== "string" ||
    typeof payload.iat !== "number" || typeof payload.exp !== "number" ||
    payload.exp - payload.iat !== MAGIC_LINK_TTL || payload.iat > Math.floor(Date.now() / 1000)
  ) throw new HttpError(401, "Claim magic link non validi");
  const source = await sourceSession(payload.sid);
  if (source.subject !== payload.sub) throw new HttpError(401, "Identita' magic link non valida");
  const consumed = await (await getRedis()).getDel(`magic-link:${payload.jti}`);
  if (consumed !== source.id) throw new HttpError(401, "Magic link gia' utilizzato o non valido");

  const context = await tokenAuthContext();
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
