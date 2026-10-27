import { bundleSecrets } from "./bundle-secrets.js";
import type { Check } from "./common.js";
import { closedSignup } from "./closed-signup.js";
import { idorRead } from "./idor-read.js";
import { idorWrite } from "./idor-write.js";
import { llmEndpoint } from "./llm.js";
import { loggedOutRead } from "./logged-out-read.js";
import { selfPromotion } from "./self-promotion.js";
import { webhookSignature } from "./webhook.js";

export const CHECK_LIST: Check[] = [
  loggedOutRead,
  idorRead,
  idorWrite,
  selfPromotion,
  closedSignup,
  bundleSecrets,
  webhookSignature,
  llmEndpoint,
];
