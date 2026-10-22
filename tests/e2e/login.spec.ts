import { expect, test, type Page } from "@playwright/test";
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from "jose";
import { Pool } from "pg";

async function startLogin(page: Page, level: "L2" | "L3") {
  const authorization = page.context().waitForEvent("request", {
    predicate: (request) => request.url().startsWith("http://localhost:4100/authorize?"),
  });
  const popup = page.waitForEvent("popup");
  await page.getByRole("button", { name: `Login con SPID ${level}` }).click();
  const window = await popup;
  const request = await authorization;
  const params = new URL(request.url()).searchParams;
  expect(params.get("acr_values")).toBe(`https://www.spid.gov.it/Spid${level}`);
  expect(params.get("prompt")).toBe("login");
  expect(params.get("code_challenge_method")).toBe("S256");
  expect(params.get("state")).toBeTruthy();
  expect(params.get("nonce")).toBeTruthy();
  return window;
}

async function login(page: Page, level: "L2" | "L3", achieved = level): Promise<string> {
  const sessionRequest = page.waitForRequest((request) => request.url().endsWith("/api/session"));
  const callbackResponse = page.context().waitForEvent("response", {
    predicate: (response) => new URL(response.url()).pathname === `/api/auth/callback/spid-${level.toLowerCase()}`,
  });
  await startLogin(page, level);
  const callback = await callbackResponse;
  expect(callback.status()).toBe(200);
  expect(callback.headers()["cache-control"]).toBe("no-store");
  expect(callback.headers()["content-security-policy"]).toContain("script-src 'nonce-");
  expect(callback.headers().location).toBeUndefined();
  const authenticated = await sessionRequest;
  const authorization = authenticated.headers().authorization;
  expect(authorization).toMatch(/^Bearer /);
  const token = authorization.slice("Bearer ".length);
  expect(token.split(".")).toHaveLength(3);
  expect(decodeProtectedHeader(token)).toMatchObject({ alg: "RS256", kid: expect.any(String) });
  await expect(page.getByRole("status")).toHaveText(`Utente autenticato - SPID ${achieved}`);
  const cookies = await page.context().cookies();
  expect(cookies.some((cookie) => /session_token|session_data|account_data/.test(cookie.name))).toBe(false);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  return token;
}

test.beforeEach(async ({ request }) => {
  await request.post("http://localhost:4100/test/mode?value=normal");
});

test("JWS/JWKS, persistent sessions, immutable step-up, revocation and memory-only browser", async ({ page, request }) => {
  const requestedUrls: string[] = [];
  page.context().on("request", (request) => requestedUrls.push(request.url()));
  await page.goto("/");
  const original = await login(page, "L2");
  const claims = decodeJwt(original);
  expect(Number(claims.exp) - Number(claims.iat)).toBe(3600);
  expect(JSON.stringify(claims)).not.toMatch(/accessToken|refreshToken|idToken|access_token|refresh_token|id_token/);
  const jwksResponse = await request.get("/api/auth/jwks");
  const jwks = await jwksResponse.json();
  expect(JSON.stringify(jwks)).not.toMatch(/privateKey|"d":|"p":|"q":/);
  const verified = await jwtVerify(original, createLocalJWKSet(jwks), {
    algorithms: ["RS256"], issuer: "http://localhost:3100", audience: "http://localhost:3100",
  });
  expect(verified.payload.sid).toBeTruthy();
  await expect(jwtVerify(original, createLocalJWKSet(jwks), {
    currentDate: new Date(Number(claims.exp) * 1000), clockTolerance: 0,
  })).rejects.toThrow();

  const newer = await login(page, "L3");
  const oldSession = await request.get("/api/session", { headers: { Authorization: `Bearer ${original}` } });
  expect(oldSession.status()).toBe(200);
  expect((await oldSession.json()).level).toBe("L2");
  expect((await request.get("/api/example", { headers: { Authorization: `Bearer ${newer}` } })).status()).toBe(200);
  expect((await request.get("/api/example")).status()).toBe(401);

  const pool = new Pool({
    connectionString: process.env.TEST_DATABASE_URL ?? "postgres://playground:test-only@localhost:5432/playground_test",
  });
  try {
    const records = await pool.query(
      'SELECT id, level, "createdAt", "expiresAt", "revokedAt" FROM "session" WHERE id = ANY($1)',
      [[claims.sid, decodeJwt(newer).sid]],
    );
    expect(records.rows).toHaveLength(2);
    for (const row of records.rows) expect(row.expiresAt.getTime() - row.createdAt.getTime()).toBe(3_600_000);
    const accounts = await pool.query('SELECT "accessToken", "refreshToken", "idToken" FROM account');
    for (const row of accounts.rows) expect(Object.values(row)).toEqual([null, null, null]);

    await page.getByRole("button", { name: "Logout e revoca" }).click();
    await expect(page.getByRole("status")).toHaveText("Utente non autenticato");
    expect((await request.get("/api/example", { headers: { Authorization: `Bearer ${newer}` } })).status()).toBe(401);
    expect((await request.get("/api/example", { headers: { Authorization: `Bearer ${original}` } })).status()).toBe(200);
    const revoked = await pool.query('SELECT "revokedAt" FROM "session" WHERE id = $1', [decodeJwt(newer).sid]);
    expect(revoked.rows[0].revokedAt).toBeInstanceOf(Date);
  } finally {
    await pool.end();
  }

  await login(page, "L2");
  await page.reload();
  await expect(page.getByRole("status")).toHaveText("Utente non autenticato");
  expect(requestedUrls.some((url) => new URL(url).pathname === "/api/token")).toBe(false);
  expect(requestedUrls.some((url) => /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(url))).toBe(false);
});

for (const mode of [
  "cancel", "lower-acr", "missing-acr", "unknown-acr", "wrong-nonce",
  "wrong-signature", "wrong-audience", "wrong-issuer", "missing-email",
  "wrong-state", "missing-state", "wrong-pkce", "different-subject",
]) {
  test(`failed step-up (${mode}) preserves the L2 bearer session`, async ({ page, request }) => {
    await page.goto("/");
    const original = await login(page, "L2");
    await request.post(`http://localhost:4100/test/mode?value=${mode}`);
    await startLogin(page, "L3");
    await expect(page.getByRole("alert")).toBeVisible();
    if (mode === "different-subject") {
      await expect(page.getByRole("alert")).toContainText("Il collegamento e' stato rifiutato");
    }
    await expect(page.getByRole("status")).toHaveText("Utente autenticato - SPID L2");
    const response = await request.get("/api/session", { headers: { Authorization: `Bearer ${original}` } });
    expect(response.status()).toBe(200);
    expect((await response.json()).level).toBe("L2");
  });
}

test("uses the achieved acr and permits a subsequent L2 login after L3", async ({ page, request }) => {
  await page.goto("/");
  await request.post("http://localhost:4100/test/mode?value=higher-acr");
  await login(page, "L2", "L3");
  await request.post("http://localhost:4100/test/mode?value=normal");
  await login(page, "L2");
});

test("ignores login messages from a different origin, window or login attempt", async ({ page, context }) => {
  await page.goto("/");
  await login(page, "L2");
  let sessionRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/session") sessionRequests++;
  });
  await context.route("http://localhost:4100/authorize?**", (route) =>
    route.fulfill({ contentType: "text/html", body: "<!doctype html><title>IdP</title>" }));
  const initiation = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/login");
  const popup = await startLogin(page, "L3");
  const { requestId } = (await initiation).postDataJSON();
  await popup.waitForLoadState();
  await popup.evaluate(({ requestId, origin }) => {
    window.opener.postMessage({ type: "spid-login", requestId, token: "wrong-origin" }, origin);
  }, { requestId, origin: "http://localhost:3100" });
  await popup.goto("/");
  await page.evaluate((requestId) => {
    window.postMessage({ type: "spid-login", requestId, token: "wrong-window" }, window.location.origin);
  }, requestId);
  await popup.evaluate((requestId) => {
    window.opener.postMessage({
      type: "spid-login", requestId: "x".repeat(43), token: "wrong-login",
    }, window.location.origin);
    window.opener.postMessage({
      type: "spid-login", requestId, error: "LoginFailed",
    }, window.location.origin);
  }, requestId);
  await expect(page.getByRole("alert")).toContainText("Login non completato");
  await expect(page.getByRole("status")).toHaveText("Utente autenticato - SPID L2");
  expect(sessionRequests).toBe(0);
});

test("rejects tampered bearer tokens, cookie auth and public token/session endpoints", async ({ page, request }) => {
  await page.goto("/");
  const token = await login(page, "L2");
  const parts = token.split(".");
  parts[1] = Buffer.from(JSON.stringify({ ...decodeJwt(token), sid: "forged" })).toString("base64url");
  expect((await request.get("/api/session", { headers: { Authorization: `Bearer ${parts.join(".")}` } })).status()).toBe(401);
  expect((await request.get("/api/session", { headers: { cookie: `better-auth.session_token=${token}` } })).status()).toBe(401);
  expect((await request.get("/api/auth/token")).status()).toBe(404);
  expect((await request.get("/api/auth/get-session")).status()).toBe(404);
  const crossOrigin = await request.post("/api/login", {
    headers: { Origin: "https://evil.example" }, data: { level: "L2", requestId: "x".repeat(43) },
  });
  expect(crossOrigin.status()).toBe(403);
  const invalidRequest = await request.post("/api/login", {
    headers: { Origin: "http://localhost:3100" }, data: { level: "L2", requestId: "invalid" },
  });
  expect(invalidRequest.status()).toBe(400);
  expect((await request.post("/api/token", { data: {} })).status()).toBe(404);
});
