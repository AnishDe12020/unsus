import { formatJsonReport, formatSarifReport, formatScanText, scanTarget } from "@unsus/core";
import type { RiskLevel } from "@unsus/core";
import { runLifecycleScriptsInDockerSandbox } from "@unsus/sandbox";
import { writeReport } from "../report-output.js";

export async function runScanCommand(args: string[]): Promise<number> {
  const seen = new Set<string>();
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (["--format", "--output", "--fail-on", "--registry"].includes(arg)) {
      if (seen.has(arg)) throw new Error(`Duplicate scan option: ${arg}`);
      seen.add(arg);
    }
    if (arg === "--fail-on") {
      if (!["safe", "low", "medium", "high", "critical"].includes(args[++index] ?? "")) throw new Error("--fail-on requires safe, low, medium, high, or critical.");
    } else if (arg === "--format") {
      if (!["text", "json", "sarif"].includes(args[++index] ?? "")) throw new Error("--format requires text, json, or sarif.");
    } else if (arg === "--registry") {
      if (!args[++index] || args[index]!.startsWith("-")) throw new Error("--registry requires a URL.");
    } else if (arg === "--output") {
      if (!args[++index] || args[index]!.startsWith("-")) throw new Error("--output requires a file path (use ./ for filenames beginning with a dash).");
    } else if (arg.startsWith("-") && !["--json", "--dynamic", "--no-dynamic", "--allow-remote-dynamic"].includes(arg)) throw new Error(`Unknown scan option: ${arg}`);
  }
  const targets = positionalArguments(args);
  const target = targets[0];
  if (targets.length !== 1 || !target) {
    throw new Error("Usage: unsus scan <target> [--format text|json|sarif] [--output PATH] [--dynamic] [--fail-on high]");
  }

  const dynamic = args.includes("--dynamic") && !args.includes("--no-dynamic");
  const requestedFormat = readOption(args, "--format");
  if (args.includes("--json") && requestedFormat && requestedFormat !== "json") throw new Error("--json cannot be combined with a non-JSON --format.");
  const format = requestedFormat ?? (args.includes("--json") ? "json" : "text");
  if (format === "sarif" && dynamic) throw new Error("SARIF reporting supports static scans only; omit --dynamic.");
  const result = await scanTarget(target, {
    ...(readOption(args, "--registry") ? { registry: readOption(args, "--registry")! } : {}),
    dynamic,
    allowRemoteDynamic: args.includes("--allow-remote-dynamic"),
    ...(dynamic
      ? {
          dynamicRunner: (pkg) =>
            runLifecycleScriptsInDockerSandbox({
              sourceRootPath: pkg.rootPath,
              packageJson: pkg.packageJson
            })
        }
      : {}),
    ...(readOption(args, "--fail-on") ? { failOn: readOption(args, "--fail-on") as RiskLevel } : {})
  });

  await writeReport(readOption(args, "--output"), format === "sarif" ? formatSarifReport(result) : format === "json" ? formatJsonReport(result) : formatScanText(result));
  if (dynamic && !result.sandbox?.enabled) return 3;
  if (result.decision === "block") {
    return 2;
  }

  if (result.decision === "warn") {
    return 1;
  }

  return 0;
}

export function firstPositional(args: string[]): string | undefined {
  return positionalArguments(args)[0];
}

export function positionalArguments(args: string[]): string[] {
  const targets: string[] = [];
  const values = new Set(["--fail-on", "--against", "--pm", "--registry", "--format", "--output"]);
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (values.has(arg)) { index++; continue; }
    if (!arg.startsWith("-")) targets.push(arg);
  }
  return targets;
}

export function readOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}
