import { randomBytes } from "node:crypto";

export const LOGIN_REQUEST_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function loginResponse(origin: string, requestId: string, token: string) {
  if (!LOGIN_REQUEST_PATTERN.test(requestId)) throw new Error("Invalid login request ID");
  const nonce = randomBytes(24).toString("base64");
  const message = JSON.stringify({ type: "spid-login", requestId, token })
    .replaceAll("<", "\\u003c").replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026").replaceAll("\u2028", "\\u2028").replaceAll("\u2029", "\\u2029");
  const targetOrigin = JSON.stringify(new URL(origin).origin);
  return new Response(`<!doctype html>
<html lang="it"><head><meta charset="utf-8"><title>Login SPID</title></head>
<body><p>Login completato. Puoi chiudere questa finestra e tornare alla pagina principale.</p>
<script nonce="${nonce}">
window.history.replaceState(null, "", "/auth/complete");
if (window.opener) {
  window.opener.postMessage(${message}, ${targetOrigin});
  window.close();
}
</script></body></html>`, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,
    },
  });
}
