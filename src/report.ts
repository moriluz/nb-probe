import type { CheckResult, DiscoveryReport, ScanReport, Severity } from "./types.js";
import { severityRank } from "./util.js";
import { VERSION } from "./version.js";

export function summarize(results: CheckResult[]): ScanReport["summary"] {
  return {
    pass: results.filter((result) => result.status === "pass").length,
    fail: results.filter((result) => result.status === "fail").length,
    skip: results.filter((result) => result.status === "skip").length,
    error: results.filter((result) => result.status === "error").length,
  };
}

export function exitCode(report: ScanReport): number {
  if (report.ownership !== "verified") return 2;
  if (report.summary.error > 0) return 1;
  const failed = report.results.some(
    (result) => result.status === "fail" && severityRank(result.severity) >= severityRank("medium"),
  );
  return failed ? 1 : 0;
}

export function formatHuman(report: ScanReport): string {
  const lines = [
    `nb-probe ${report.version}`,
    `target: ${report.target}`,
    `ownership: ${report.ownership}`,
  ];
  if (report.supabaseUrl) lines.push(`supabase: ${report.supabaseUrl}`);
  if (report.message) lines.push(report.message);
  if (report.discovery) lines.push(...formatDiscovery(report.discovery));
  lines.push("");
  for (const result of report.results) {
    lines.push(formatResult(result));
    lines.push("");
  }
  const summary = report.summary;
  lines.push(
    `${summary.pass} passed, ${summary.fail} failed, ${summary.skip} skipped, ${summary.error} errors`,
  );
  for (const note of report.notes) lines.push(`note: ${note}`);
  return `${lines.join("\n")}\n`;
}

function formatDiscovery(discovery: DiscoveryReport): string[] {
  const lines: string[] = [];
  if (discovery.schema === "openapi") {
    lines.push(`schema: OpenAPI (${discovery.tables.length} tables)`);
    return lines;
  }
  const files = discovery.files;
  lines.push(
    `schema: refused (HTTP ${discovery.openApi.status ?? "error"}), discovered from ${files.scripts} scripts, ${files.sourceMaps} source maps and PostgREST`,
  );
  const shown = discovery.tables.filter((table) => table.status !== "not-found" || !table.sources.includes("guess"));
  if (shown.length === 0) lines.push("tables: none");
  for (const table of shown) {
    const parts = [`  ${table.name.padEnd(20)} ${table.status.padEnd(9)} ${table.sources.join(", ")}`];
    if (table.suggestedFor) parts.push(`(suggested for ${table.suggestedFor})`);
    if (table.ownerColumn) parts.push(`owner: ${table.ownerColumn}`);
    if (table.note) parts.push(`- ${table.note}`);
    lines.push(parts.join(" "));
  }
  if (discovery.rpcs.length) lines.push(`rpc (seen in bundle, not called): ${discovery.rpcs.join(", ")}`);
  if (discovery.buckets.length) lines.push(`storage buckets (seen in bundle): ${discovery.buckets.join(", ")}`);
  if (files.errors.length) lines.push(`bundle fetch errors: ${files.errors.slice(0, 3).join("; ")}`);
  return lines;
}

function formatResult(result: CheckResult): string {
  const status = result.status.toUpperCase().padEnd(5);
  const severity = result.severity.padEnd(8);
  const lines = [`${status}  ${severity}  ${result.id}`, `       ${result.summary}`];
  if (result.fix) lines.push(`       fix: ${result.fix}`);
  if (result.repro) {
    lines.push("");
    lines.push(result.repro);
  }
  return lines.join("\n");
}

export function formatJson(report: ScanReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function buildReport(args: {
  target: string;
  supabaseUrl?: string;
  ownership: ScanReport["ownership"];
  message?: string;
  startedAt: string;
  results: CheckResult[];
  notes: string[];
  discovery?: DiscoveryReport;
}): ScanReport {
  const report: ScanReport = {
    tool: "nb-probe",
    version: VERSION,
    schemaVersion: 1,
    target: args.target,
    ownership: args.ownership,
    startedAt: args.startedAt,
    finishedAt: new Date().toISOString(),
    results: args.results,
    summary: summarize(args.results),
    notes: args.notes,
  };
  if (args.supabaseUrl) report.supabaseUrl = args.supabaseUrl;
  if (args.message) report.message = args.message;
  if (args.discovery) report.discovery = args.discovery;
  return report;
}

export function worstSeverity(values: Severity[]): Severity {
  return values.reduce<Severity>((worst, next) => (severityRank(next) > severityRank(worst) ? next : worst), "info");
}
