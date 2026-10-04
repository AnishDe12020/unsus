import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, mkdir, writeFile, readFile, rm, access } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as tar from "tar";
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const cli = path.join(repo, "packages/cli/dist/index.js");
function command(args: string[], cwd: string, env = process.env) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { cwd, env });
    let stdout = "", stderr = "";
    child.stdout.on("data", (data) => { stdout += data; });
    child.stderr.on("data", (data) => { stderr += data; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("installer rejects unsupported managers and mutable local targets before npm runs", async () => {
  const local = await command(["install", path.join(repo, "fixtures/benign/normal-package")], repo);
  assert.equal(local.code, 3);
  assert.match(local.stderr, /registry package|local.*not supported/i);
  const pm = await command(["install", "fixture", "--pm", "bun"], repo);
  assert.equal(pm.code, 3);
  assert.match(pm.stderr, /npm.*only|only.*npm/i);
});

test("installer uses exact verified bytes and disables root and transitive scripts despite npm config", { timeout: 60_000 }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-test-install-"));
  const project = path.join(root, "project");
  const bodies = new Map<string, Buffer>();
  let directDownloads = 0;
  let packument: unknown;
  const server = createServer((req, res) => {
    if (req.url === "/synthetic-direct") { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(packument)); return; }
    if (req.url === "/direct.tgz") directDownloads++;
    const body = bodies.get(req.url ?? "");
    if (body) { res.end(body); return; }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const registry = `http://127.0.0.1:${address.port}`;
  try {
    await mkdir(project);
    await writeFile(path.join(project, "package.json"), JSON.stringify({ name: "test-consumer", version: "1.0.0", scripts: { postinstall: "node -e \"require('fs').writeFileSync('ROOT-RAN', 'yes')\"" } }));
    await writeFile(path.join(project, ".npmrc"), "ignore-scripts=false\n");
    for (const which of ["transitive", "direct"]) {
      const dir = path.join(root, which);
      await mkdir(path.join(dir, "package"), { recursive: true });
      await writeFile(path.join(dir, "package/package.json"), JSON.stringify({ name: `synthetic-${which}`, version: "1.0.0", scripts: { postinstall: "node postinstall.js" }, ...(which === "direct" ? { dependencies: { "synthetic-transitive": `${registry}/transitive.tgz` } } : {}) }));
      await writeFile(path.join(dir, "package/postinstall.js"), "require('fs').writeFileSync('SCRIPT-RAN', 'yes');");
      await writeFile(path.join(dir, "package/index.js"), `module.exports = '${which}-verified';`);
      const archive = path.join(dir, "pkg.tgz");
      await tar.c({ file: archive, cwd: dir, gzip: true }, ["package"]);
      bodies.set(`/${which}.tgz`, await readFile(archive));
    }
    const direct = bodies.get("/direct.tgz")!;
    packument = { name: "synthetic-direct", "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name: "synthetic-direct", version: "1.0.0", dist: { tarball: `${registry}/direct.tgz`, integrity: `sha512-${createHash("sha512").update(direct).digest("base64")}` } } } };
    const result = await command(["install", "synthetic-direct", "--registry", registry, "--force", "--json"], project, { ...process.env, npm_config_ignore_scripts: "false", npm_config_cache: path.join(root, "npm-cache") });
    assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.coverage.dependenciesAnalyzed, false);
    assert.equal(directDownloads, 1, "npm must not refetch the mutable registry target");
    for (const marker of ["ROOT-RAN", "node_modules/synthetic-direct/SCRIPT-RAN", "node_modules/synthetic-transitive/SCRIPT-RAN"]) await assert.rejects(access(path.join(project, marker)));
    assert.match(await readFile(path.join(project, "node_modules/synthetic-direct/index.js"), "utf8"), /direct-verified/);
    const pkg = JSON.parse(await readFile(path.join(project, "package.json"), "utf8"));
    assert.match(pkg.dependencies["synthetic-direct"], /^file:\.unsus\/artifacts\/[a-f0-9]+\.tgz$/);
    assert.deepEqual(await readFile(path.join(project, pkg.dependencies["synthetic-direct"].slice(5))), direct);
    // A fresh checkout with the retained artifact and lockfile can reproduce the install.
    await rm(path.join(project, "node_modules"), { recursive: true });
    const { spawnSync } = await import("node:child_process");
    const ci = spawnSync("npm", ["ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: project, encoding: "utf8", env: { ...process.env, npm_config_cache: path.join(root, "npm-cache") } });
    assert.equal(ci.status, 0, ci.stderr);
    await assert.rejects(access(path.join(project, "ROOT-RAN")));
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); await rm(root, { recursive: true, force: true }); }
});
