import type { Severity } from "./types.js";
import { decodeJwtPayload, previewSecret } from "./util.js";

export type SecretKind = "service_role" | "sb_secret" | "stripe_secret" | "source_map";

export interface SecretHit {
  kind: SecretKind;
  file: string;
  preview: string;
  severity: Severity;
}

const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const SB_SECRET_RE = /\bsb_secret_[A-Za-z0-9_-]{8,}\b/g;
const STRIPE_RE = /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b/g;
const SOURCE_MAP_RE = /[#@]\s*sourceMappingURL\s*=/;

export function findSecrets(
  files: { file: string; text: string }[],
  ignore: string[] = [],
): SecretHit[] {
  const ignored = new Set(ignore.filter(Boolean));
  const hits: SecretHit[] = [];
  const seen = new Set<string>();

  const add = (hit: SecretHit, dedupeKey: string) => {
    if (seen.has(dedupeKey) || hits.length >= 20) return;
    seen.add(dedupeKey);
    hits.push(hit);
  };

  for (const { file, text } of files) {
    for (const match of text.matchAll(JWT_RE)) {
      const token = match[0];
      if (!token || ignored.has(token)) continue;
      const payload = decodeJwtPayload(token);
      if (payload?.role !== "service_role") continue;
      add(
        {
          kind: "service_role",
          file,
          preview: previewSecret(token),
          severity: "critical",
        },
        `service_role|${file}|${token}`,
      );
    }

    for (const match of text.matchAll(SB_SECRET_RE)) {
      const token = match[0];
      if (!token || ignored.has(token)) continue;
      add(
        {
          kind: "sb_secret",
          file,
          preview: previewSecret(token),
          severity: "critical",
        },
        `sb_secret|${file}|${token}`,
      );
    }

    for (const match of text.matchAll(STRIPE_RE)) {
      const token = match[0];
      if (!token || ignored.has(token)) continue;
      const live = token.includes("_live_");
      add(
        {
          kind: "stripe_secret",
          file,
          preview: previewSecret(token),
          severity: live ? "critical" : "high",
        },
        `stripe_secret|${file}|${token}`,
      );
    }

    if (SOURCE_MAP_RE.test(text)) {
      add(
        {
          kind: "source_map",
          file,
          preview: "sourceMappingURL",
          severity: "low",
        },
        `source_map|${file}`,
      );
    }
    SOURCE_MAP_RE.lastIndex = 0;
  }

  return hits;
}
