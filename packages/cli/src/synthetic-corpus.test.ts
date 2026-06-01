import assert from "node:assert/strict";
import { test } from "node:test";
import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import type { RiskLevel } from "@unsus/core";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const manifestPath = path.join(repoRoot, "benchmarks/synthetic/manifest.json");
const runnerPath = path.join(repoRoot, "scripts/benchmarks/run-synthetic-corpus.mjs");

interface SyntheticCase {
  id: string;
  kind: "scan" | "diff";
  target: string;
  against?: string;
  expectedExit: 0 | 1 | 2;
  expectedRisk: RiskLevel;
  expectedDecision?: "allow" | "warn" | "block";
}

interface SyntheticManifest {
  safety: {
    noRealMalware: boolean;
    localOnly: boolean;
    noHostLifecycleExecution: boolean;
  };
  cases: SyntheticCase[];
}

async function readManifest(): Promise<SyntheticManifest> {
  return JSON.parse(await readFile(manifestPath, "utf8")) as SyntheticManifest;
}

test("synthetic benchmark manifest is local-only and uses harmless fixtures", async () => {
  const manifest = await readManifest();

  assert.equal(manifest.safety.noRealMalware, true);
  assert.equal(manifest.safety.localOnly, true);
  assert.equal(manifest.safety.noHostLifecycleExecution, true);
  assert.ok(manifest.cases.length >= 4);

  for (const benchmarkCase of manifest.cases) {
    assert.match(benchmarkCase.id, /^[a-z0-9-]+$/);
    assert.ok(benchmarkCase.target.startsWith("benchmarks/synthetic/"), benchmarkCase.target);
    assert.ok(!benchmarkCase.target.includes("node_modules"));
    assert.ok(benchmarkCase.expectedExit === 0 || benchmarkCase.expectedExit === 1 || benchmarkCase.expectedExit === 2);
    if (benchmarkCase.kind === "diff") {
      assert.ok(benchmarkCase.against?.startsWith("benchmarks/synthetic/"), benchmarkCase.id);
    }
  }

  const manifestText = await readFile(manifestPath, "utf8");
  assert.match(manifestText, /FAKE_TEST_TOKEN/);
  assert.doesNotMatch(manifestText, /GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|DATABASE_URL/);
});

test("synthetic benchmark runner exists and is executable", async () => {
  await access(runnerPath, constants.X_OK);
});

test("synthetic benchmark runner verifies expected scan and diff outcomes", () => {
  const result = spawnSync(process.execPath, [runnerPath, "--json"], {
    cwd: repoRoot,
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout) as {
    summary: { passed: number; failed: number };
    results: Array<{ id: string; actualExit: number; expectedExit: number }>;
  };

  assert.equal(output.summary.failed, 0);
  assert.ok(output.summary.passed >= 4);
  assert.ok(output.results.some((entry) => entry.id === "diff-new-install-env-network" && entry.actualExit === 2));
  assert.ok(output.results.every((entry) => entry.actualExit === entry.expectedExit));
});
