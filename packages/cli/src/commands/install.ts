import { spawn } from "node:child_process";

import { formatJsonReport, formatScanText, scanTarget } from "@unsus/core";

import { firstPositional, readOption } from "./scan.js";

const PACKAGE_MANAGERS = new Set(["npm", "bun", "pnpm"]);

export async function runInstallCommand(args: string[]): Promise<number> {
  const target = firstPositional(args);
  if (!target) {
    throw new Error("Usage: unsus install <package> [--pm npm|bun|pnpm] [--force] [--json] [--yes]");
  }

  const pm = readOption(args, "--pm") ?? "npm";
  if (!PACKAGE_MANAGERS.has(pm)) {
    throw new Error(`Unsupported package manager: ${pm}`);
  }

  const result = await scanTarget(target, { dynamic: true });
  if (args.includes("--json")) {
    process.stdout.write(formatJsonReport(result));
  } else {
    process.stdout.write(formatScanText(result));
  }

  if (result.decision === "block" && !args.includes("--force")) {
    console.error("Install blocked by unsus policy. Use --force only after manual review.");
    return 3;
  }

  if (result.decision === "warn" && !args.includes("--yes") && !args.includes("--force")) {
    console.error("Install requires --yes after reviewing warnings.");
    return 2;
  }

  if (args.includes("--force")) {
    console.error("FORCE OVERRIDE: installing despite unsus findings.");
  }

  return runPackageManagerInstall(pm, target);
}

function runPackageManagerInstall(pm: string, target: string): Promise<number> {
  const commandArgs =
    pm === "npm" ? ["install", target] : pm === "pnpm" ? ["add", target] : ["add", target];

  return new Promise((resolve, reject) => {
    const child = spawn(pm, commandArgs, {
      stdio: "inherit",
      env: process.env
    });

    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 1));
  });
}
