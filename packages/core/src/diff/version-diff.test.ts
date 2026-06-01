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
