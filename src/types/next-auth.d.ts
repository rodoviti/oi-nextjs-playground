import type { DefaultSession } from "next-auth";
import type { SpidLevel } from "../lib/oidc";

declare module "next-auth" {
  interface Session {
    user: { id: string } & DefaultSession["user"];
    level: SpidLevel;
    acr: string;
    provider: string;
    startedAt: string;
    authTime?: number;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    level: SpidLevel;
    acr: string;
    provider: string;
    sessionStartedAt: number;
    sessionExpiresAt: number;
    authTime?: number;
  }
}
