# Repository instructions

## Commands

Use npm and the committed lockfile. Node.js >= 20.19; CI uses Node.js 22.

```sh
npm ci
npm run db:migrate
npm run dev
npm run lint
npm run typecheck
npm test
npm test -- tests/jwt.test.ts tests/handoff.test.ts
npm run build
npx playwright install --with-deps chromium
npm run test:e2e
```

Build and unit tests need no live services. Browser tests need a dedicated
PostgreSQL database (`TEST_DATABASE_URL`) and Redis (`TEST_REDIS_URL`).
Playwright migrates the test DB and starts/stops app port 3100 and mock IdP
port 4100. Keep one worker because IdP failure modes are shared state.
Rebuild before browser tests. Never run tests against production services.
See [README.md](../README.md) for environment and Dev Container setup.

## Architecture

Next.js App Router / TypeScript, Better Auth 1.7.12, PostgreSQL sessions,
RS256 JWS bearer tokens and Redis revocation. No session JWE, persistent
browser token storage or session cookies.

- `src/auth.config.ts` creates request-local OIDC configuration; never cache
  this instance across requests, since it captures verified login metadata.
- `src/lib/auth-schema.ts` shares fields between OIDC auth and JWT-only auth.
  JWT verification/signing must not depend on IdP discovery being available.
- `src/lib/jwt.ts` delegates signing/key management to Better Auth `jwt()`
  and verifies JWS with jose plus Redis on every protected request.
- `src/lib/handoff.ts` provides atomic, PKCE-bound, 60-second codes on Redis.
- The client page uses popup login and keeps the JWT only in React memory.
  Refresh loses login. Only temporary OIDC state cookies are allowed.
- PostgreSQL migrations are explicit, versioned SQL, transactionally applied
  by `scripts/migrate.ts`. No implicit migrations at application startup.

## Authentication invariants

- Login L2/L3 derives achieved level from the verified ID token's `acr`.
  L3 satisfies L2, not the reverse. Unknown/missing acr is rejected.
- Persist SPID level/acr/provider/authTime on each session, not the shared
  user. Step-up must not alter the identity/privileges of prior sessions.
- Account linking requires matching verified issuer AND subject, never
  email alone. Keep the binding validation for both linking and sign-in.
- Each successful login starts exactly 3,600 seconds. JWT iat/exp reflect
  that original deadline; reads, later issuance and client updates never renew it.
- Step-up is new login, not logout first. Failure preserves the current token.
- Logout writes `revoked:<sid>` to Redis until absolute exp before marking
  the DB session's revokedAt. Retain the record for future audit correlation.
  Revoke all JWTs of that session, not sessions from other logins or the IdP.
- Infrastructure failures fail closed with explicit logging and 503.
  Never claim successful logout before persisting the revocation.
- Redis is authorization state, not disposable cache. Preserve AOF/noeviction.
- Access/refresh/ID tokens must not enter session JWTs, account DB records
  or the UI. JWS payloads are readable; retain only minimal identity/metadata.
- Do not expose Better Auth cookie-based session/token/update endpoints.
  Only the OIDC callbacks and JWKS are public under `/api/auth`.
- Handoff codes require verifier, same-origin initiation/exchange and
  origin/source validation for postMessage. Never put JWTs in URLs.

## Conventions and tests

UI text is Italian; identifiers are English. `@/*` resolves to `src/*`.
Use the native BETTER_AUTH_URL and BETTER_AUTH_SECRET environment handling,
without custom baseURL/secret assignment.

Unit tests stub environments with vi.stubEnv and restore them. Crypto tests
fake only Date. Test exact expiry, issuer/audience/algorithms, revocation,
Redis failure, handoff replay/PKCE, and immutable session projections.
Browser tests use the real production app and `tests/e2e/mock-idp.ts`.
Keep the synthetic IdP out of application routes and reset modes per test.
