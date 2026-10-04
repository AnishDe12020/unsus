import { formatProjectText, scanProject } from "@unsus/core";
import type { RiskLevel } from "@unsus/core";
import { writeReport } from "../report-output.js";

export async function runProjectCommand(args: string[]): Promise<number> {
  let target: string | undefined, output: string | undefined, failOn: RiskLevel | undefined;
  let maxPackages = 20, format = "text", includeDev = false;
  const seen = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (["--max-packages", "--format", "--output", "--fail-on"].includes(arg)) {
      if (seen.has(arg)) throw new Error(`Duplicate project option: ${arg}`);
      seen.add(arg);
      const value = args[++i];
      if (!value || value.startsWith("-")) throw new Error(`${arg} requires a value.`);
      if (arg === "--max-packages") { if (!/^\d+$/.test(value)) throw new Error("--max-packages must be from 1 to 100."); maxPackages = Number(value); }
      if (arg === "--format") { if (!["text", "json"].includes(value)) throw new Error("Project --format supports text or json."); format = value; }
      if (arg === "--output") output = value;
      if (arg === "--fail-on") { if (!["safe", "low", "medium", "high", "critical"].includes(value)) throw new Error("Invalid --fail-on level."); failOn = value as RiskLevel; }
    } else if (arg === "--json") continue;
    else if (arg === "--include-dev") includeDev = true;
    else if (arg.startsWith("-")) throw new Error(`Unknown project option: ${arg}`);
    else if (target !== undefined) throw new Error("Usage: unsus project [directory] [--json] [--max-packages N] [--include-dev]");
    else target = arg;
  }
  if (args.includes("--json")) {
    if (seen.has("--format") && format !== "json") throw new Error("--json cannot be combined with a non-JSON --format.");
    format = "json";
  }
  const result = await scanProject(target ?? ".", { includeDev, maxPackages, ...(failOn ? { failOn } : {}) });
  await writeReport(output, format === "json" ? JSON.stringify(result, null, 2) + "\n" : formatProjectText(result));
  return result.exitCode;
}
