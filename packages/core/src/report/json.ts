import type { ScanResult, VersionDiffResult } from "../types.js";

export function formatJsonReport(report: ScanResult | VersionDiffResult): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
