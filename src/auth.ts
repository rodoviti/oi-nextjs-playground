import NextAuth from "next-auth";
import { createAuthConfig } from "./auth.config";

export const { auth, handlers, signIn, signOut } = NextAuth(() => createAuthConfig());
