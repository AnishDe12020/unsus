import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const cli = fileURLToPath(new URL("./index.js", import.meta.url));
test("machine operational errors are one structured document and never overwrite a prior report", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-errors-"));
  try {
    for (const args of [["scan", "./missing", "--json"], ["diff", "./missing", "--against", "./other", "--json"], ["install", "./local", "--json"], ["project", "./missing", "--json"], ["unknown", "--json"]]) {
      const run = spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: "utf8" });
      assert.equal(run.status, 3);
      const error = JSON.parse(run.stdout);
      assert.equal(error.ok, false); assert.equal(error.exitCode, 3);
      assert.equal(error.error.code, "OPERATIONAL_ERROR"); assert.ok(error.error.message);
      assert.equal(run.stderr, "");
    }
    const output = path.join(root, "previous.json"); await writeFile(output, 'previous');
    const run = spawnSync(process.execPath, [cli, "scan", "./missing", "--format", "json", "--output", output], { cwd: root, encoding: "utf8" });
    assert.equal(run.status, 3); assert.equal(run.stdout, "");
    assert.equal(JSON.parse(run.stderr).error.code, "OPERATIONAL_ERROR");
    assert.equal(await readFile(output, "utf8"), 'previous');
    await writeFile(path.join(root, "package.json"), '{"dependencies":{"missing":"1.0.0"}}');
    const project = spawnSync(process.execPath, [cli, "project", "--json"], { cwd: root, encoding: "utf8" });
    assert.equal(project.status, 1); assert.equal(JSON.parse(project.stdout).coverage.unresolved, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});
