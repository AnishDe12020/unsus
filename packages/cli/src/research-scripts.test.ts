import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const datadogScript = path.join(repoRoot, "scripts/research/build-datadog-npm-candidates.mjs");

test("DataDog candidate builder converts exact npm versions and reports unversioned entries", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "unsus-datadog-test-"));
  const input = path.join(directory, "manifest.json");
  const output = path.join(directory, "candidates.json");
  await writeFile(
    input,
    `${JSON.stringify(
      {
        "malicious-all-versions": null,
        "versioned-one": ["1.0.0", "1.0.1"],
        "@scope/versioned-two": ["2.0.0"]
      },
      null,
      2
    )}\n`
  );

  const result = spawnSync(process.execPath, [datadogScript, "--input", input, "--output", output, "--json"], {
    cwd: repoRoot,
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout) as {
    summary: { totalPackages: number; exactCandidates: number; unversionedPackages: number };
  };
  const candidates = JSON.parse(await readFile(output, "utf8")) as {
    kind: string;
    candidates: Array<{ id: string; package: string; source: string; notes: string }>;
  };

  assert.equal(report.summary.totalPackages, 3);
  assert.equal(report.summary.exactCandidates, 3);
  assert.equal(report.summary.unversionedPackages, 1);
  assert.equal(candidates.kind, "unsus-real-world-npm-candidate-list");
  assert.deepEqual(
    candidates.candidates.map((candidate) => candidate.package).sort(),
    ["@scope/versioned-two@2.0.0", "versioned-one@1.0.0", "versioned-one@1.0.1"]
  );
  assert.ok(candidates.candidates.every((candidate) => candidate.source.includes("DataDog")));
  assert.ok(candidates.candidates.every((candidate) => candidate.notes.includes("DataDog")));
});
