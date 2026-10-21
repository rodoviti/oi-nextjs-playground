import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SPID OIDC Playground",
  description: "PoC Next.js e Auth.js per login SPID L2/L3 e step-up.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="it">
      <body>{children}</body>
    </html>
  );
}
