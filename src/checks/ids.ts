export const CHECK_IDS = [
  "logged-out-read",
  "idor-read",
  "idor-write",
  "self-promotion",
  "closed-signup",
  "bundle-secrets",
  "webhook-signature",
  "llm-endpoint",
] as const;

export type CheckId = (typeof CHECK_IDS)[number];
