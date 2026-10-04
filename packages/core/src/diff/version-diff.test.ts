import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { extractLocalPackage } from "../extract/local.js";
import { compareExtractedPackages } from "./version-diff.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");

test("compareExtractedPackages detects new postinstall, dependencies, and suspicious added files", async () => {
  const from = await extractLocalPackage(path.join(repoRoot, "fixtures/benign/normal-package"));
  const to = await extractLocalPackage(path.join(repoRoot, "fixtures/suspicious/postinstall-env-network"));

  const diff = compareExtractedPackages(from, to);

  assert.ok(diff.addedFiles.includes("install.js"));
  assert.ok(diff.removedFiles.includes("index.js"));
  assert.ok(diff.findings.some((finding) => finding.type === "new_lifecycle_script"));
  assert.ok(diff.findings.some((finding) => finding.type === "new_suspicious_source_file"));
});

test("diff detects equal-sized changes beyond the binary header and text read limit", async () => {
  const fs = await import("node:fs/promises");
  const os = await import("node:os");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-diff-bytes-"));
  try {
    for (const name of ["before", "after"]) {
      await fs.mkdir(path.join(root, name));
      await fs.writeFile(path.join(root, name, "package.json"), '{"name":"fixture","version":"1.0.0"}');
      const bytes = Buffer.alloc(128, 65);
      if (name === "after") bytes[100] = 66;
      for (const file of ["large.js", "payload.bin"]) await fs.writeFile(path.join(root, name, file), bytes);
    }
    const from = await extractLocalPackage(path.join(root, "before"), { maxTextBytes: 64, hashOmittedFiles: true });
    const to = await extractLocalPackage(path.join(root, "after"), { maxTextBytes: 64, hashOmittedFiles: true });
    assert.deepEqual(compareExtractedPackages(from, to).changedFiles, ["large.js", "payload.bin"]);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("diff reports new behavior in modified source without treating dev scripts as install hooks", async () => {
  const from = await extractLocalPackage(path.join(repoRoot, "fixtures/benign/normal-package"));
  const to = { ...from, packageJson: { ...from.packageJson, scripts: { test: "node test.js" } }, files: from.files.map(file => file.path === "index.js" ? { ...file, content: 'eval("harmless synthetic string");' } : file) };
  const diff = compareExtractedPackages(from, to);
  assert.ok(diff.findings.some(finding => finding.type === "changed_suspicious_source_file" && finding.file === "index.js"));
  assert.ok(!diff.findings.some(finding => finding.type === "new_lifecycle_script"));
});
