#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const manifestPath = path.join(repoRoot, "benchmarks/synthetic/manifest.json");
const cliPath = path.join(repoRoot, "packages/cli/dist/index.js");
const jsonMode = process.argv.includes("--json");

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));

if (!manifest.safety?.noRealMalware || !manifest.safety?.localOnly || !manifest.safety?.noHostLifecycleExecution) {
  throw new Error("Synthetic corpus manifest safety flags are incomplete.");
}

const results = [];

for (const benchmarkCase of manifest.cases ?? []) {
  const args =
    benchmarkCase.kind === "diff"
      ? ["diff", benchmarkCase.target, "--against", benchmarkCase.against, "--json"]
      : ["scan", benchmarkCase.target, "--json"];

  if (args.some((arg) => typeof arg !== "string" || !arg.startsWith("--") && arg.includes("node_modules"))) {
    throw new Error(`Unsafe benchmark path in ${benchmarkCase.id}`);
  }

  const child = spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "",
      HOME: "/tmp/unsus-synthetic-benchmark-home"
    }
  });

  let parsedReport = undefined;
  try {
    parsedReport = child.stdout.trim() ? JSON.parse(child.stdout) : undefined;
  } catch {
    parsedReport = undefined;
  }

  const actualExit = child.status ?? 3;
  const passed =
    actualExit === benchmarkCase.expectedExit &&
    (benchmarkCase.kind !== "scan" || !benchmarkCase.expectedDecision || parsedReport?.decision === benchmarkCase.expectedDecision);

  results.push({
    id: benchmarkCase.id,
    kind: benchmarkCase.kind,
    expectedExit: benchmarkCase.expectedExit,
    actualExit,
    expectedDecision: benchmarkCase.expectedDecision,
    actualDecision: parsedReport?.decision,
    expectedRisk: benchmarkCase.expectedRisk,
    actualRisk: parsedReport?.riskLevel,
    passed,
    stderr: child.stderr.trim()
  });
}

const failed = results.filter((result) => !result.passed);
const output = {
  summary: {
    total: results.length,
    passed: results.length - failed.length,
    failed: failed.length
  },
  results
};

if (jsonMode) {
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
} else {
  process.stdout.write("UNSUS SYNTHETIC BENCHMARKS\n\n");
  for (const result of results) {
    const marker = result.passed ? "PASS" : "FAIL";
    process.stdout.write(`${marker} ${result.id}: exit ${result.actualExit} expected ${result.expectedExit}\n`);
  }
  process.stdout.write(`\nPassed ${output.summary.passed}/${output.summary.total}\n`);
}

process.exit(failed.length === 0 ? 0 : 1);
