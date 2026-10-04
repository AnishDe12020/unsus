import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { extractLocalPackage } from "./local.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");

test("extractLocalPackage reads package identity and source files without node_modules", async () => {
  const fixturePath = path.join(repoRoot, "fixtures/benign/normal-package");

  const extracted = await extractLocalPackage(fixturePath);

  assert.equal(extracted.identity.name, "normal-package");
  assert.equal(extracted.identity.version, "1.0.0");
  assert.equal(extracted.isLocal, true);
  assert.equal(extracted.packageJson.name, "normal-package");
  assert.ok(extracted.files.some((file) => file.path === "index.js" && file.kind === "source"));
  assert.ok(extracted.files.some((file) => file.path === "package.json" && file.kind === "json"));
  assert.ok(extracted.files.every((file) => !file.path.includes("node_modules")));
});

test("distribution source is scanned and omitted text coverage is reported", async () => {
  const fs = await import("node:fs/promises");
  const os = await import("node:os");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-test-local-"));
  try {
    await fs.mkdir(path.join(root, "dist"));
    await fs.writeFile(path.join(root, "package.json"), '{"name":"fixture","version":"1.0.0"}');
    await fs.writeFile(path.join(root, "dist/index.js"), 'eval("fixture");');
    await fs.writeFile(path.join(root, "large.js"), "a".repeat(1024));
    const pkg = await extractLocalPackage(root, { maxTextBytes: 128 });
    assert.ok(pkg.files.some((file) => file.path === "dist/index.js" && file.content));
    assert.equal(pkg.files.find(file => file.path === "large.js")?.contentHash, undefined);
    const { scanExtractedPackage } = await import("../scan.js");
    const report = scanExtractedPackage(pkg);
    assert.ok("coverage" in report);
    assert.equal((report.coverage as { complete: boolean }).complete, false);
    assert.notEqual(report.decision, "allow");
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
