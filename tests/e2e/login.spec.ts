import { expect, test, type BrowserContext, type Page } from "@playwright/test";

async function login(page: Page, level: "L2" | "L3") {
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
  await expect(page.getByRole("status")).toHaveText(`Utente autenticato - SPID ${level}`);
}

async function sessionCookie(context: BrowserContext) {
  const cookie = (await context.cookies()).find((cookie) => cookie.name === "authjs.session-token");
  expect(cookie).toBeDefined();
  expect(cookie!.httpOnly).toBe(true);
  expect(cookie!.sameSite).toBe("Lax");
  expect(cookie!.value.split(".")).toHaveLength(5);
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
  const details = JSON.parse(await page.getByLabel("Dettagli della sessione").innerText());
  expect(Date.parse(details.expires) - Date.parse(details.startedAt)).toBe(3_600_000);
  expect(JSON.stringify(details)).not.toMatch(/access_token|id_token|refresh_token/);

  await login(page, "L3");
  expect((await sessionCookie(context)).value).not.toBe(original.value);
  const newDetails = JSON.parse(await page.getByLabel("Dettagli della sessione").innerText());
  expect(Date.parse(newDetails.expires) - Date.parse(newDetails.startedAt)).toBe(3_600_000);

  const previousContext = await browser.newContext();
  try {
    await previousContext.addCookies([original]);
    const previousPage = await previousContext.newPage();
    await previousPage.goto("http://localhost:3100/");
    await expect(previousPage.getByRole("status")).toHaveText("Utente autenticato - SPID L2");
    const before = await previousPage.getByLabel("Dettagli della sessione").innerText();
    const refreshed = await previousContext.request.get("http://localhost:3100/api/auth/session");
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

for (const mode of ["cancel", "lower-acr", "missing-acr"]) {
  test(`failed step-up (${mode}) preserves the L2 session`, async ({ page, context, request }) => {
    await page.goto("/");
    await login(page, "L2");
    const original = await sessionCookie(context);
    await request.post(`http://localhost:4100/test/mode?value=${mode}`);
    await page.getByRole("button", { name: "Login con SPID L3" }).click();
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(page.getByRole("status")).toHaveText("Utente autenticato - SPID L2");
    expect((await sessionCookie(context)).value).toBe(original.value);
  });
}
