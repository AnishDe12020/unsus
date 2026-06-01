import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const cliPath = path.join(repoRoot, "packages/cli/dist/index.js");

test("CLI scan emits JSON report for local fixture", () => {
  const target = path.join(repoRoot, "fixtures/benign/normal-package");
  const result = spawnSync(process.execPath, [cliPath, "scan", target, "--json"], {
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout) as { package: { name: string }; decision: string };
  assert.equal(report.package.name, "normal-package");
  assert.equal(report.decision, "allow");
});
