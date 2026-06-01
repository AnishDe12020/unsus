import { readFile } from "node:fs/promises";

import { formatDiffText, formatScanText } from "@unsus/core";
import type { ScanResult, VersionDiffResult } from "@unsus/core";

import { firstPositional } from "./scan.js";

export async function runExplainCommand(args: string[]): Promise<number> {
  const reportPath = firstPositional(args);
  if (!reportPath) {
    throw new Error("Usage: unsus explain <report.json>");
  }

  const parsed = JSON.parse(await readFile(reportPath, "utf8")) as ScanResult | VersionDiffResult;
  if ("riskScore" in parsed) {
    process.stdout.write(formatScanText(parsed));
  } else {
    process.stdout.write(formatDiffText(parsed));
  }

  return 0;
}
