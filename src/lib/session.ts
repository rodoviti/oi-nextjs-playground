import { decode, encode, type JWT, type JWTDecodeParams, type JWTEncodeParams } from "next-auth/jwt";

export const SESSION_TTL = 60 * 60;

function expiration(token: JWT): number {
  if (
    typeof token.sessionExpiresAt !== "number" ||
    !Number.isInteger(token.sessionExpiresAt)
  ) {
    throw new Error("Missing absolute session expiration");
  }
  return token.sessionExpiresAt;
}

export async function encodeSession(params: JWTEncodeParams): Promise<string> {
  if (!params.token) throw new Error("Missing session token");
  // Auth.js re-encodes JWTs on session reads; never extend their absolute lifetime.
  const remaining = expiration(params.token) - Math.floor(Date.now() / 1000);
  return encode({ ...params, maxAge: Math.max(0, remaining) });
}

export async function decodeSession(params: JWTDecodeParams): Promise<JWT | null> {
  const token = await decode(params);
  if (!token) return null;
  // Enforce the exact deadline, including Auth.js's default JWT clock tolerance.
  return expiration(token) <= Math.floor(Date.now() / 1000) ? null : token;
}
