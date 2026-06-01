import { formatJsonReport, formatScanText, scanTarget } from "@unsus/core";
import type { RiskLevel } from "@unsus/core";

export async function runScanCommand(args: string[]): Promise<number> {
  const target = firstPositional(args);
  if (!target) {
    throw new Error("Usage: unsus scan <target> [--json] [--dynamic] [--fail-on high]");
  }

  const result = await scanTarget(target, {
    dynamic: args.includes("--dynamic") && !args.includes("--no-dynamic"),
    ...(readOption(args, "--fail-on") ? { failOn: readOption(args, "--fail-on") as RiskLevel } : {})
  });

  process.stdout.write(args.includes("--json") ? formatJsonReport(result) : formatScanText(result));
  if (result.decision === "block") {
    return 2;
  }

  if (result.decision === "warn") {
    return 1;
  }

  return 0;
}

export function firstPositional(args: string[]): string | undefined {
  return args.find((arg, index) => !arg.startsWith("-") && (index === 0 || !args[index - 1]?.startsWith("--")));
}

export function readOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}
