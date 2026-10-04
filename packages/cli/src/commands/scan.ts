import { formatJsonReport, formatScanText, scanTarget } from "@unsus/core";
import type { RiskLevel } from "@unsus/core";
import { runLifecycleScriptsInDockerSandbox } from "@unsus/sandbox";

export async function runScanCommand(args: string[]): Promise<number> {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--fail-on") {
      if (!["safe", "low", "medium", "high", "critical"].includes(args[++index] ?? "")) throw new Error("--fail-on requires safe, low, medium, high, or critical.");
    } else if (arg.startsWith("-") && !["--json", "--dynamic", "--no-dynamic", "--allow-remote-dynamic"].includes(arg)) throw new Error(`Unknown scan option: ${arg}`);
  }
  const targets = positionalArguments(args);
  const target = targets[0];
  if (targets.length !== 1 || !target) {
    throw new Error("Usage: unsus scan <target> [--json] [--dynamic] [--fail-on high]");
  }

  const dynamic = args.includes("--dynamic") && !args.includes("--no-dynamic");
  const result = await scanTarget(target, {
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

  process.stdout.write(args.includes("--json") ? formatJsonReport(result) : formatScanText(result));
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
  const values = new Set(["--fail-on", "--against", "--pm", "--registry"]);
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
