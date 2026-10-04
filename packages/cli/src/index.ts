#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { runDiffCommand } from "./commands/diff.js";
import { runExplainCommand } from "./commands/explain.js";
import { runInstallCommand } from "./commands/install.js";
import { runScanCommand } from "./commands/scan.js";
import { runProjectCommand } from "./commands/project.js";
import { reportOperationalError } from "./errors.js";

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;

  try {
    if (command === "--version" || command === "-v") {
      console.log(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
      return 0;
    }
    if (command && Object.hasOwn(commandHelp, command) && args.some(arg => arg === "--help" || arg === "-h")) {
      console.log(commandHelp[command]);
      return 0;
    }
    switch (command) {
      case "project":
        return await runProjectCommand(args);
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
        throw new Error(`Unknown command: ${command}. Run unsus --help.`);
    }
  } catch (error) {
    reportOperationalError(error, argv);
    return 3;
  }
}

function printHelp(): void {
  console.log(`unsus - heuristic package scanner and guarded npm installer

Usage:
  unsus scan <target> [--format text|json|sarif] [--output PATH] [--json] [--dynamic] [--fail-on high]
  unsus diff <pkg>@<new> --against <pkg>@<old> [--registry URL] [--json]
  unsus project [directory] [--json] [--max-packages N] [--include-dev]
  unsus install <registry-package> [--registry URL] [--dynamic] [--force] [--json] [--yes]
  unsus explain <report.json>
  unsus --version

Run unsus <command> --help for options and examples.
`);
}

const commandHelp: Record<string, string> = {
  scan: `Usage: unsus scan <directory-or-registry-package> [options]

Inspect a direct package without executing its code by default.
  --format <format>       text (default), json, or sarif (static scans only)
  --json                  Alias for --format json
  --output <PATH>         Atomically save the report instead of writing stdout
  --registry <URL>        Use a compatible HTTPS registry for registry targets
  --fail-on <level>        Block at safe, low, medium, high, or critical (default: high)
  --dynamic               Observe lifecycle scripts in Docker
  --no-dynamic            Disable observation, overriding --dynamic
  --allow-remote-dynamic   Permit Docker observation of a registry package

Example: unsus scan . --format sarif --output report.sarif
Output parent directories must exist; existing reports are replaced after a successful write.
Dependencies are not scanned. Exit codes: 0 allowed, 1 review, 2 blocked, 3 failure.`,
  project: `Usage: unsus project [directory] [--format text|json] [--json] [--output PATH]
                       [--max-packages N] [--include-dev] [--fail-on level]

Inspect installed direct dependencies offline. Default limit: 20 packages; maximum: 100.
Missing, linked, mismatched, and unsupported dependencies are reported, never installed.
No registry or lockfile integrity verification, transitive scanning, or code execution.
Exit codes: 0 allowed, 1 review/incomplete coverage, 2 blocked, 3 inspection failure.`,
  diff: `Usage: unsus diff <new-target> --against <old-target> [--registry URL] [--json]

Compare local directories or registry packages, including full-byte file changes.
Example: unsus diff package-name@1.2.0 --against package-name@1.1.0
Dependencies are not scanned. Exit codes: 0 no warnings, 1 review, 2 blocked, 3 failure.`,
  install: `Usage: unsus install <registry-package> [options]

Scan and install the same verified archive with npm lifecycle scripts disabled.
  --registry <URL>   Use a compatible HTTPS registry
  --dynamic          Observe lifecycle scripts in Docker before installation
  --yes              Accept review-level warnings
  --force            Override a blocked scan; never enables lifecycle scripts
  --json             Emit the scan report on stdout; npm progress uses stderr

Run inside a project with package.json. Local paths, Git URLs, bun, and pnpm are unsupported.
Keep .unsus/artifacts/ with package.json and package-lock.json; npm references these archives.
Example: unsus install package-name@1.2.3
Dependencies are not scanned. Exit codes: 0 installed, 1 review, 2 blocked, 3 failure.`,
  explain: `Usage: unsus explain <report.json>

Render a saved scan or version-diff JSON report as readable text.
Example: unsus explain report.json`
};

process.exitCode = await main(process.argv.slice(2));
