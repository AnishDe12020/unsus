import { diffTargets, formatDiffText, formatJsonReport } from "@unsus/core";

import { positionalArguments, readOption } from "./scan.js";

export async function runDiffCommand(args: string[]): Promise<number> {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--against") {
      if (!args[index + 1] || args[index + 1]!.startsWith("--")) throw new Error("--against requires a value.");
      index++;
    } else if (arg.startsWith("-") && arg !== "--json") throw new Error(`Unknown diff option: ${arg}`);
  }
  const targets = positionalArguments(args);
  const target = targets[0];
  const against = readOption(args, "--against");

  if (targets.length !== 1 || !target || !against) {
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
