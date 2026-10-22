import { betterAuth } from "better-auth";
import { createAuthConfig } from "./auth.config";

export function getAuth() {
  // Without a database, Better Auth uses memory internally; keep it request-local.
  return betterAuth(createAuthConfig());
}
