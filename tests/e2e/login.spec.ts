import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { symmetricDecodeJWT } from "better-auth/crypto";

async function login(page: Page, level: "L2" | "L3", achieved = level) {
  const authorization = page.waitForRequest((request) => request.url().startsWith("http://localhost:4100/authorize?"));
  await page.getByRole("button", { name: `Login con SPID ${level}` }).click();
  const request = await authorization;
  const params = new URL(request.url()).searchParams;
  expect(params.get("acr_values")).toBe(`https://www.spid.gov.it/Spid${level}`);
  expect(params.get("prompt")).toBe("login");
  expect(params.get("code_challenge_method")).toBe("S256");
  expect(params.get("state")).toBeTruthy();
  expect(params.get("nonce")).toBeTruthy();
  await expect(page).toHaveURL("http://localhost:3100/");
  await expect(page.getByRole("status")).toHaveText(`Utente autenticato - SPID ${achieved}`);
}

async function sessionCookie(context: BrowserContext) {
  const cookies = await context.cookies();
  const cookie = cookies.find((cookie) => cookie.name === "better-auth.session_data");
  expect(cookie).toBeDefined();
  expect(cookie!.httpOnly).toBe(true);
  expect(cookie!.sameSite).toBe("Lax");
  expect(cookie!.value.split(".")).toHaveLength(5);
  expect(cookies.some((cookie) => cookie.name.includes("account_data"))).toBe(false);
  const payload = await symmetricDecodeJWT(
    cookie!.value,
    "e2e-only-secret-not-for-production-32-characters",
    "better-auth-session",
  );
  expect(payload).not.toBeNull();
  expect(JSON.stringify(payload)).not.toMatch(/accessToken|refreshToken|idToken|access_token|refresh_token|id_token/);
  return cookie!;
}

test.beforeEach(async ({ request }) => {
  await request.post("http://localhost:4100/test/mode?value=normal");
});

test("L2 -> L3 creates a new session without revoking the old JWE", async ({ page, context, browser }) => {
  await page.goto("/");
  await expect(page.getByRole("status")).toHaveText("Utente non autenticato");
  await login(page, "L2");
  const original = await sessionCookie(context);
  const originalCookies = await context.cookies();
  const details = JSON.parse(await page.getByLabel("Dettagli della sessione").innerText());
  expect(Date.parse(details.expires) - Date.parse(details.startedAt)).toBe(3_600_000);
  expect(JSON.stringify(details)).not.toMatch(/access_token|id_token|refresh_token/);

  await login(page, "L3");
  expect((await sessionCookie(context)).value).not.toBe(original.value);
  const newDetails = JSON.parse(await page.getByLabel("Dettagli della sessione").innerText());
  expect(Date.parse(newDetails.expires) - Date.parse(newDetails.startedAt)).toBe(3_600_000);

  const previousContext = await browser.newContext();
  try {
    await previousContext.addCookies(originalCookies);
    const previousPage = await previousContext.newPage();
    await previousPage.goto("http://localhost:3100/");
    await expect(previousPage.getByRole("status")).toHaveText("Utente autenticato - SPID L2");
    const before = await previousPage.getByLabel("Dettagli della sessione").innerText();
    const refreshed = await previousContext.request.get("http://localhost:3100/api/auth/get-session");
    expect((await refreshed.json()).expires).toBe(details.expires);
    await previousPage.reload();
    expect(await previousPage.getByLabel("Dettagli della sessione").innerText()).toBe(before);

    await page.getByRole("button", { name: "Logout locale" }).click();
    await expect(page.getByRole("status")).toHaveText("Utente non autenticato");
    await previousPage.reload();
    await expect(previousPage.getByRole("status")).toHaveText("Utente autenticato - SPID L2");
  } finally {
    await previousContext.close();
  }
});

for (const mode of [
  "cancel", "lower-acr", "missing-acr", "unknown-acr", "wrong-nonce",
  "wrong-signature", "wrong-audience", "wrong-issuer", "missing-email",
  "wrong-state", "missing-state", "wrong-pkce",
]) {
  test(`failed step-up (${mode}) preserves the L2 session`, async ({ page, context, request }) => {
    await page.goto("/");
    await login(page, "L2");
    const original = await sessionCookie(context);
    await request.post(`http://localhost:4100/test/mode?value=${mode}`);
    await page.getByRole("button", { name: "Login con SPID L3" }).click();
    await expect(page.getByRole("main").getByRole("alert")).toBeVisible();
    await expect(page.getByRole("status")).toHaveText("Utente autenticato - SPID L2");
    if (["lower-acr", "missing-acr", "unknown-acr"].includes(mode)) {
      await expect(page).toHaveURL(/error=InsufficientAcr/);
    }
    expect((await sessionCookie(context)).value).toBe(original.value);
  });
}

test("uses the achieved acr and allows a subsequent L2 login after L3", async ({ page, request }) => {
  await page.goto("/");
  await request.post("http://localhost:4100/test/mode?value=higher-acr");
  await login(page, "L2", "L3");
  const higher = JSON.parse(await page.getByLabel("Dettagli della sessione").innerText());
  expect(higher.provider).toBe("spid-l2");
  expect(higher.acr).toBe("https://www.spid.gov.it/SpidL3");
  await request.post("http://localhost:4100/test/mode?value=normal");
  await login(page, "L2");
});
