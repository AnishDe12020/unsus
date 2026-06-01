import { diffTargets, formatDiffText, formatJsonReport } from "@unsus/core";

import { firstPositional, readOption } from "./scan.js";

export async function runDiffCommand(args: string[]): Promise<number> {
  const target = firstPositional(args);
  const against = readOption(args, "--against");

  if (!target || !against) {
    throw new Error("Usage: unsus diff <pkg>@<new> --against <pkg>@<old> [--json]");
  }

  const result = await diffTargets(target, against);
  process.stdout.write(args.includes("--json") ? formatJsonReport(result) : formatDiffText(result));
  if (result.findings.some((finding) => finding.severity === "danger" || finding.severity === "critical")) {
    return 2;
  }

  if (result.findings.some((finding) => finding.severity === "warning")) {
    return 1;
  }

  return 0;
}
