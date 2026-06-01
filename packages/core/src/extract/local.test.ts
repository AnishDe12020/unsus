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
