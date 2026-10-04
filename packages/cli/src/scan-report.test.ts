import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const cli = path.join(repo, "packages/cli/dist/index.js");
const benign = path.join(repo, "fixtures/benign/normal-package");
const blocked = path.join(repo, "fixtures/suspicious/postinstall-env-network");
const scan = (...args: string[]) => spawnSync(process.execPath, [cli, "scan", ...args], { encoding: "utf8" });

test("scan formats and atomic output preserve policy exits with clean report streams", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-report-"));
  try {
    const incomplete = path.join(root, "incomplete");
    await mkdir(incomplete);
    await writeFile(path.join(incomplete, "package.json"), '{"name":"incomplete","version":"1.0.0"}');
    await writeFile(path.join(incomplete, "large.js"), "x".repeat(256 * 1024 + 1));
    const output = path.join(root, "report.sarif");
    for (const [target, status] of [[benign, 0], [incomplete, 1], [blocked, 2]] as const) {
      await writeFile(output, "old report");
      const result = scan(target, "--format", "sarif", "--output", output);
      assert.equal(result.status, status, result.stderr);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "");
      const sarif = JSON.parse(await readFile(output, "utf8"));
      assert.equal(sarif.runs[0].invocations[0].exitCode, status);
      assert.equal(sarif.runs[0].properties.coverage.dependenciesAnalyzed, false);
    }
    const stdout = scan(blocked, "--format", "sarif");
    assert.equal(stdout.status, 2);
    assert.equal(JSON.parse(stdout.stdout).version, "2.1.0");
    assert.equal(stdout.stderr, "");
    for (const flags of [["--json"], ["--format", "json"], ["--json", "--format", "json"]]) {
      const result = scan(benign, ...flags, "--output", output);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(await readFile(output, "utf8")).package.name, "normal-package");
    }
    assert.match(scan(benign, "--format", "text").stdout, /UNSUS PACKAGE FIREWALL/);
    assert.deepEqual((await readdir(root)).sort(), ["incomplete", "report.sarif"]);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("invalid formats and failed report writes fail operationally without clobbering prior files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-report-failure-"));
  try {
    const output = path.join(root, "previous.json");
    await writeFile(output, "previous report");
    for (const args of [
      ["--format", "xml"], ["--format"], ["--output"], ["--output", "--json"],
      ["--format", "sarif", "--json"], ["--format", "sarif", "--dynamic"],
      ["--format", "json", "--format", "sarif"]
    ]) {
      const result = scan(benign, ...args);
      assert.equal(result.status, 3, result.stderr);
      if (result.stdout) assert.equal(JSON.parse(result.stdout).error.code, "OPERATIONAL_ERROR");
    }
    const missingParent = scan(blocked, "--format", "sarif", "--output", path.join(root, "missing", "report.sarif"));
    assert.equal(missingParent.status, 3);
    assert.equal(missingParent.stdout, "");
    const directory = scan(benign, "--output", root);
    assert.equal(directory.status, 3);
    if (process.platform !== "win32") {
      const link = path.join(root, "linked.json");
      await symlink(output, link);
      const result = scan(benign, "--format", "json", "--output", link);
      assert.equal(result.status, 3);
      assert.match(result.stderr, /symbolic link/);
    }
    assert.equal(await readFile(output, "utf8"), "previous report");
    assert.ok(!(await readdir(root)).some(name => name.endsWith(".tmp")));
  } finally { await rm(root, { recursive: true, force: true }); }
});
