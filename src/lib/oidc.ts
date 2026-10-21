export const SPID_LEVELS = ["L2", "L3"] as const;
export type SpidLevel = (typeof SPID_LEVELS)[number];

export type OidcSettings = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  acr: Record<SpidLevel, string>;
};

export function readOidcSettings(): OidcSettings {
  function required(name: string) {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`Missing environment variable: ${name}`);
    return value;
  }

  const issuer = required("OIDC_ISSUER");
  const url = new URL(issuer);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && url.hostname === "localhost")) {
    throw new Error("OIDC_ISSUER must use HTTPS (HTTP is allowed only on localhost)");
  }
  const acr = {
    L2: process.env.OIDC_ACR_L2?.trim() || "https://www.spid.gov.it/SpidL2",
    L3: process.env.OIDC_ACR_L3?.trim() || "https://www.spid.gov.it/SpidL3",
  };
  if (acr.L2 === acr.L3) throw new Error("L2 and L3 must use distinct acr values");

  return {
    issuer,
    clientId: required("OIDC_CLIENT_ID"),
    clientSecret: required("OIDC_CLIENT_SECRET"),
    acr,
  };
}

export function achievedLevel(acr: unknown, settings: OidcSettings): SpidLevel | null {
  return SPID_LEVELS.find((level) => settings.acr[level] === acr) ?? null;
}

export function satisfiesLevel(actual: SpidLevel | null, requested: SpidLevel): boolean {
  return actual === "L3" || (actual === "L2" && requested === "L2");
}
