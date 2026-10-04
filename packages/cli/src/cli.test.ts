import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const cliPath = path.join(repoRoot, "packages/cli/dist/index.js");

test("version and command help work without resolving packages or installing anything", () => {
  const version = spawnSync(process.execPath, [cliPath, "--version"], { encoding: "utf8" });
  assert.equal(version.status, 0, version.stderr);
  assert.match(version.stdout, /^0\.1\.0\n$/);
  for (const command of ["scan", "diff", "install", "project", "explain"]) {
    const help = spawnSync(process.execPath, [cliPath, command, "--help"], { encoding: "utf8" });
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, new RegExp(`Usage: unsus ${command}`));
  }
});

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

test("CLI scan exits 0 for benign fixture", () => {
  const target = path.join(repoRoot, "fixtures/benign/normal-package");
  const result = spawnSync(process.execPath, [cliPath, "scan", target], {
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
});

test("CLI scan exits 2 for blocked suspicious fixture", () => {
  const target = path.join(repoRoot, "fixtures/suspicious/postinstall-env-network");
  const result = spawnSync(process.execPath, [cliPath, "scan", target], {
    encoding: "utf8"
  });

  assert.equal(result.status, 2, result.stderr);
});

test("CLI scan exits 3 for invalid local path", () => {
  const target = path.join(repoRoot, "fixtures/no-such-package");
  const result = spawnSync(process.execPath, [cliPath, "scan", target], {
    encoding: "utf8"
  });

  assert.equal(result.status, 3);
});

test("CLI diff exits 2 when diff findings include block-level risk", () => {
  const target = path.join(repoRoot, "fixtures/suspicious/postinstall-env-network");
  const against = path.join(repoRoot, "fixtures/benign/normal-package");
  const result = spawnSync(process.execPath, [cliPath, "diff", target, "--against", against], {
    encoding: "utf8"
  });

  assert.equal(result.status, 2, result.stderr);
});

test("CLI diff exits 0 when no block-level risk is detected", () => {
  const target = path.join(repoRoot, "fixtures/benign/normal-package");
  const result = spawnSync(process.execPath, [cliPath, "diff", target, "--against", target], {
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
});

test("scan recognizes a positional target after boolean flags", () => {
  const result = spawnSync(process.execPath, [cliPath, "scan", "--json", path.join(repoRoot, "fixtures/benign/normal-package")], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).package.name, "normal-package");
});

test("scan rejects invalid fail-on levels and unknown options", () => {
  for (const args of [["--fail-on", "hgh"], ["--dyanmic"], ["extra-target"]]) {
    const result = spawnSync(process.execPath, [cliPath, "scan", path.join(repoRoot, "fixtures/benign/normal-package"), ...args], { encoding: "utf8" });
    assert.equal(result.status, 3, result.stderr);
  }
});


test("diff rejects missing option values before resolving packages", () => {
  const result = spawnSync(process.execPath, [cliPath, "diff", "ms@2.1.3", "--against", "--json"], { encoding: "utf8" });
  assert.equal(result.status, 3);
  assert.equal(result.stderr, "");
  assert.match(JSON.parse(result.stdout).error.message, /--against requires a value/);
  assert.equal(JSON.parse(result.stdout).error.code, "OPERATIONAL_ERROR");
});
