# Repository instructions

## Commands

Use npm with the committed `package-lock.json`. Node.js >= 20.19 is required;
CI uses Node.js 22.

```sh
npm ci
npm run dev                 # Development server on localhost:3000
npm run build
npm start                   # Production server; requires a completed build
npm run lint                # ESLint flat config with Next.js + TypeScript rules
npm run typecheck
npm test                    # Vitest, tests/**/*.test.ts only
npm test -- tests/session.test.ts
npm test -- tests/session.test.ts -t "does not extend the deadline"
npx playwright install chromium
npm run test:e2e             # Requires a current production build
npm run test:e2e -- tests/e2e/login.spec.ts -g "L2 -> L3"
```

CI runs lint, typecheck, unit tests, build, Chromium installation
(`npx playwright install --with-deps chromium` on Linux), then browser tests.

Playwright starts and stops both the production app on `localhost:3100` and the
synthetic OIDC IdP on `localhost:4100`, with its own test environment variables.
Both ports must be free; existing servers are not reused. Browser tests use one
worker because the mock IdP's failure mode is shared mutable state. Rebuild after
application changes before running browser tests.

For development against a real IdP, configure `BETTER_AUTH_URL`, `BETTER_AUTH_SECRET`,
`OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` in the process environment
or an untracked `.env.local`. Optional `OIDC_ACR_L2` / `OIDC_ACR_L3` override the
default SPID acr URLs. Register both `/api/auth/callback/spid-l2` and
`/api/auth/callback/spid-l3` on the same OIDC client. See `README.md` for setup.
Unit tests and the build do not require real IdP credentials.

## Architecture

This is a Next.js App Router / TypeScript PoC using Auth.js (`next-auth` v5 beta)
with encrypted, stateless sessions and no database.

`src/auth.ts` lazily initializes Auth.js through `createAuthConfig()` in
`src/auth.config.ts`. The catch-all API route exports its GET/POST handlers.
The configuration creates two OIDC providers sharing issuer and client
credentials but selecting different minimum SPID levels with `acr_values`.
Both use `prompt=login` and PKCE, state, and nonce checks.

Authentication callbacks form a pipeline: `signIn` checks the returned ID token's
actual `acr` against the requested minimum; `jwt` creates fresh session claims
only on a successful login; `session` exposes minimal identity and metadata to
the UI. `src/lib/oidc.ts` centralizes environment validation and level mapping.
The integration assumes discovery, Authorization Code Flow, PKCE S256,
`client_secret_basic`, and the `openid profile email` scopes.

`src/app/page.tsx` is the force-dynamic server-rendered login/status page.
Forms invoke server actions using the Auth.js server helpers; there is no
client-side session provider. Login/error redirects return to `/`.
`src/lib/session.ts` wraps Auth.js JWE encoding/decoding to enforce an absolute
deadline. `src/types/next-auth.d.ts` augments both Session and JWT types.

## Authentication and session invariants

- Step-up is a new login, never sign-out followed by login. Successful login
  replaces the browser's current cookie without revoking the previous JWE;
  cancellation or rejection preserves the previous session.
- Logout is local cookie removal, not IdP logout or token revocation. Previously
  issued JWEs remain valid until their original deadlines. Login L2 after L3 is
  allowed to replace the session with a lower-level one.
- Derive the achieved level from the returned ID token's `acr`, not the selected
  button or provider ID. L3 satisfies L2; L2 does not satisfy L3. Missing or unknown
  acr values are rejected. The configurable L2/L3 identifiers must be distinct.
- Keep JWE encryption delegated to `next-auth/jwt`. `sessionStartedAt` and
  `sessionExpiresAt` are epoch seconds set 3,600 seconds apart on each successful
  login. Reads and client updates must not reset them.
- Preserve both custom `jwt.encode` and `jwt.decode`: `maxAge` alone permits
  sliding expiration. Encoding uses the remaining lifetime; decoding rejects at
  the exact absolute deadline despite Auth.js's default clock tolerance.
  Browser cookie reissuance must not extend effective session validity.
- The session callback projects that same absolute deadline as ISO `expires`
  and converts the start timestamp to ISO `startedAt`. When changing claims,
  update the JWT callback, session projection, and module augmentations together.
- Keep access, refresh, and ID tokens out of the session JWE and UI. Only minimal
  identity and session metadata are retained.
- Issuers must use HTTPS except HTTP on `localhost`. Required OIDC settings fail
  explicitly when missing; acr defaults and validation live in `readOidcSettings`.

## UI, errors, and test conventions

UI text is Italian; code identifiers are English. `@/*` resolves to `src/*`.
Keep auth actions server-side. The login action catches `AuthError` to log a
diagnostic and redirect to a user-visible error; it rethrows other exceptions,
including Next.js redirect control flow. Insufficient acr is logged and
redirected to `/?error=InsufficientAcr`.

Unit tests import helpers/configuration directly, stub environment variables with
`vi.stubEnv`, and restore them after each test. Session tests fake only `Date`,
leaving asynchronous crypto operational, and check the exact expiry boundary.

Browser tests exercise the actual production app against
`tests/e2e/mock-idp.ts`, which provides discovery, signed ID tokens, and PKCE
validation. `/test/mode` selects cancellation or invalid acr responses and is
reset before each test. Keep this test-only IdP outside application routes.
The step-up regression test replays the old cookie in a separate browser context
to verify that it survives both the new login and local logout.
