import type { ScanResult } from "@unsus/core";

export class InstallFailure extends Error {
  constructor(message: string, readonly report: ScanResult) { super(message); }
}

/** Keep exactly one machine-readable document, including failures after an install scan. */
export function reportOperationalError(error: unknown, args: string[]): void {
  const message = error instanceof Error ? error.message : String(error);
  const format = args.includes("--format") ? args[args.indexOf("--format") + 1] : undefined;
  const machine = args.includes("--json") || (args.includes("--format") && ["json", "sarif"].includes(format ?? ""));
  if (!machine) { console.error(message); return; }
  const causeCode = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" && /^[A-Z][A-Z0-9_]+$/.test(error.code) ? error.code : undefined;
  const document = {
    ok: false, exitCode: 3,
    error: { code: error instanceof InstallFailure ? "INSTALL_FAILED" : "OPERATIONAL_ERROR", message, ...(causeCode ? { causeCode } : {}) },
    ...(error instanceof InstallFailure ? { report: error.report } : {})
  };
  // Never replace a previous saved report on failure, or mix JSON into SARIF stdout.
  const stream = args.includes("--output") || format === "sarif" ? process.stderr : process.stdout;
  stream.write(JSON.stringify(document, null, 2) + "\n");
}
