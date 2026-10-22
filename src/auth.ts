import { betterAuth } from "better-auth";
import { createAuthConfig } from "./auth.config";

export function getAuth() {
  // The verified OIDC metadata captured by the configuration is request-local.
  return betterAuth(createAuthConfig());
}
