#!/usr/bin/env node

import { runDiffCommand } from "./commands/diff.js";
import { runExplainCommand } from "./commands/explain.js";
import { runInstallCommand } from "./commands/install.js";
import { runScanCommand } from "./commands/scan.js";

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;

  try {
    switch (command) {
      case "scan":
        return await runScanCommand(args);
      case "diff":
        return await runDiffCommand(args);
      case "install":
        return await runInstallCommand(args);
      case "explain":
        return await runExplainCommand(args);
      case undefined:
      case "-h":
      case "--help":
        printHelp();
        return 0;
      default:
        console.error(`Unknown command: ${command}`);
        printHelp();
        return 2;
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

function printHelp(): void {
  console.log(`unsus - local package firewall

Usage:
  unsus scan <target> [--json] [--dynamic] [--no-dynamic] [--fail-on high]
  unsus diff <pkg>@<new> --against <pkg>@<old> [--json]
  unsus install <package> [--pm npm|bun|pnpm] [--force] [--json] [--yes]
  unsus explain <report.json>
`);
}

process.exitCode = await main(process.argv.slice(2));
