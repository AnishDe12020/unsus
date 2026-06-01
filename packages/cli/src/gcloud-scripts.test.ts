import assert from "node:assert/strict";
import { constants } from "node:fs";
import { access, readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

const scripts = [
  "scripts/gcloud/create-sandbox-vm.sh",
  "scripts/gcloud/destroy-sandbox-vm.sh",
  "scripts/gcloud/sync-repo-to-vm.sh",
  "scripts/gcloud/run-fixture-on-vm.sh"
];

test("gcloud sandbox scripts exist and are executable", async () => {
  for (const script of scripts) {
    const absolutePath = path.join(repoRoot, script);
    await access(absolutePath, constants.F_OK | constants.X_OK);
  }
});

test("sync script excludes credential and build-heavy paths", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/sync-repo-to-vm.sh"), "utf8");

  for (const required of [".git", "node_modules", ".env", ".npmrc", ".ssh", ".aws", ".config", "dist", "*.tsbuildinfo"]) {
    assert.match(content, new RegExp(`--exclude=['"]?${escapeRegExp(required)}`));
  }

  assert.match(content, /npm install --ignore-scripts/);
  assert.doesNotMatch(content, /HOME\/\.\{0,1\}/);
});

test("destroy script requires explicit confirmation and targets one configured VM", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/destroy-sandbox-vm.sh"), "utf8");

  assert.match(content, /UNSUS_GCLOUD_YES/);
  assert.match(content, /read -r/);
  assert.match(content, /gcloud compute instances delete/);
  assert.doesNotMatch(content, /instances delete .*--regexp/);
});

test("create script uses no service account and labels the VM", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/create-sandbox-vm.sh"), "utf8");

  assert.match(content, /--no-service-account/);
  assert.match(content, /--no-scopes/);
  assert.match(content, /app=unsus/);
  assert.match(content, /purpose=sandbox/);
  assert.match(content, /ttl=manual-delete/);
  assert.match(content, /cost/i);
});

test("gcloud docs include safety boundaries", async () => {
  const docs = [
    await readFile(path.join(repoRoot, "docs/gcloud-sandbox.md"), "utf8"),
    await readFile(path.join(repoRoot, "scripts/gcloud/README.md"), "utf8")
  ].join("\n");

  assert.match(docs, /no host secrets/i);
  assert.match(docs, /no real malware/i);
  assert.match(docs, /remote npm dynamic/i);
  assert.match(docs, /destroy-sandbox-vm\.sh/);
});

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
