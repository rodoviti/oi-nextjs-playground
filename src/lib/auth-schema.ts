export const userFields = {
  subject: { type: "string", required: true },
  issuer: { type: "string", required: true },
} as const;

export const sessionFields = {
  ...userFields,
  level: { type: "string", required: true, input: false },
  acr: { type: "string", required: true, input: false },
  provider: { type: "string", required: true, input: false },
  authTime: { type: "number", required: false, input: false },
  revokedAt: { type: "date", required: false, input: false },
} as const;
