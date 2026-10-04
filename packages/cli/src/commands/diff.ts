import { diffTargets, formatDiffText, formatJsonReport } from "@unsus/core";

import { positionalArguments, readOption } from "./scan.js";

export async function runDiffCommand(args: string[]): Promise<number> {
  const seen = new Set<string>();
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--against" || arg === "--registry") {
      if (seen.has(arg)) throw new Error(`Duplicate diff option: ${arg}`);
      seen.add(arg);
      if (!args[index + 1] || args[index + 1]!.startsWith("--")) throw new Error(`${arg} requires a value.`);
      index++;
    } else if (arg.startsWith("-") && arg !== "--json") throw new Error(`Unknown diff option: ${arg}`);
  }
  const targets = positionalArguments(args);
  const target = targets[0];
  const against = readOption(args, "--against");

  if (targets.length !== 1 || !target || !against) {
    throw new Error("Usage: unsus diff <pkg>@<new> --against <pkg>@<old> [--json]");
  }

  const registry = readOption(args, "--registry");
  const result = await diffTargets(target, against, registry ? { registry } : {});
  process.stdout.write(args.includes("--json") ? formatJsonReport(result) : formatDiffText(result));
  if (result.findings.some((finding) => finding.severity === "danger" || finding.severity === "critical")) {
    return 2;
  }

  if (result.findings.some((finding) => finding.severity === "warning")) {
    return 1;
  }

  return 0;
}
