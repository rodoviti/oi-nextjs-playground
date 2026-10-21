import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

// Test-only IdP: automatic consent, synthetic identity, no external network calls.
async function main() {
  const issuer = "http://localhost:4100";
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "test-key", alg: "RS256", use: "sig" };
  const codes = new Map<string, URLSearchParams>();
  let mode = "normal";

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url!, issuer);
      res.setHeader("Content-Type", "application/json");
      if (url.pathname === "/.well-known/openid-configuration") {
        res.end(JSON.stringify({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          userinfo_endpoint: `${issuer}/userinfo`,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
          code_challenge_methods_supported: ["S256"],
        }));
      } else if (url.pathname === "/jwks") {
        res.end(JSON.stringify({ keys: [jwk] }));
      } else if (url.pathname === "/test/mode" && req.method === "POST") {
        mode = url.searchParams.get("value") ?? "normal";
        res.end("{}");
      } else if (url.pathname === "/authorize") {
        const callback = url.searchParams.get("redirect_uri");
        if (!["http://localhost:3100/api/auth/callback/spid-l2", "http://localhost:3100/api/auth/callback/spid-l3"].includes(callback ?? "")) {
          res.writeHead(400).end(JSON.stringify({ error: "invalid_redirect_uri" }));
          return;
        }
        const target = new URL(callback!);
        target.searchParams.set("state", url.searchParams.get("state")!);
        if (mode === "cancel") {
          target.searchParams.set("error", "access_denied");
        } else {
          const code = randomUUID();
          codes.set(code, url.searchParams);
          target.searchParams.set("code", code);
        }
        res.writeHead(302, { Location: target.toString() }).end();
      } else if (url.pathname === "/token" && req.method === "POST") {
        let body = "";
        for await (const chunk of req) body += chunk;
        const params = new URLSearchParams(body);
        const authorization = codes.get(params.get("code") ?? "");
        codes.delete(params.get("code") ?? "");
        const challenge = createHash("sha256").update(params.get("code_verifier") ?? "").digest("base64url");
        if (
          !authorization ||
          params.get("grant_type") !== "authorization_code" ||
          params.get("redirect_uri") !== authorization.get("redirect_uri") ||
          authorization.get("client_id") !== "test-client" ||
          req.headers.authorization !== `Basic ${Buffer.from("test-client:test-secret").toString("base64")}` ||
          challenge !== authorization.get("code_challenge")
        ) {
          res.writeHead(400).end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
        const claims: Record<string, unknown> = {
          sub: "synthetic-user",
          name: "Utente Demo",
          email: "demo@example.test",
          nonce: authorization.get("nonce"),
          auth_time: Math.floor(Date.now() / 1000),
        };
        if (mode !== "missing-acr") {
          claims.acr = mode === "lower-acr"
            ? "https://www.spid.gov.it/SpidL2"
            : authorization.get("acr_values");
        }
        const idToken = await new SignJWT(claims)
          .setProtectedHeader({ alg: "RS256", kid: "test-key" })
          .setIssuer(issuer)
          .setAudience("test-client")
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        res.end(JSON.stringify({
          access_token: "synthetic-access-token",
          token_type: "Bearer",
          expires_in: 300,
          id_token: idToken,
        }));
      } else {
        res.writeHead(404).end(JSON.stringify({ error: "not_found" }));
      }
    } catch (error) {
      console.error("[mock-idp]", error);
      res.writeHead(500).end(JSON.stringify({ error: "server_error" }));
    }
  });

  server.listen(4100, "localhost", () => console.log(`Test IdP ready at ${issuer}`));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
