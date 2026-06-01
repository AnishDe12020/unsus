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
  "scripts/gcloud/run-fixture-on-vm.sh",
  "scripts/gcloud/run-remote-npm-on-vm.sh",
  "scripts/gcloud/check-malware-readiness.sh",
  "scripts/gcloud/run-malicious-samples-on-vm.sh",
  "scripts/gcloud/status-sandbox-vm.sh"
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
  assert.match(content, /unsus_wait_for_apt/);
  assert.match(content, /SSH not ready yet/);
  assert.match(content, /app=unsus/);
  assert.match(content, /purpose=sandbox/);
  assert.match(content, /ttl=manual-delete/);
  assert.match(content, /cost/i);
});

test("sync script suppresses macOS metadata and excludes incremental build state", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/sync-repo-to-vm.sh"), "utf8");

  assert.match(content, /COPYFILE_DISABLE=1/);
  assert.match(content, /--no-xattrs/);
  assert.match(content, /--no-mac-metadata/);
  assert.match(content, /--exclude='\*\.tsbuildinfo'/);
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

test("fixture runner pre-pulls sandbox image before timed lifecycle scans", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/run-fixture-on-vm.sh"), "utf8");

  assert.match(content, /docker pull node:22-bookworm-slim/);
  assert.match(content, /scan fixtures\/suspicious\/postinstall-env-network --dynamic/);
  assert.match(content, /scan fixtures\/benign\/install-script-build-package --dynamic/);
});

test("remote npm runner requires explicit opt-in and remote package input", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/run-remote-npm-on-vm.sh"), "utf8");

  assert.match(content, /UNSUS_ALLOW_REMOTE_NPM_DYNAMIC/);
  assert.match(content, /UNSUS_REMOTE_NPM_PACKAGE/);
  assert.match(content, /--allow-remote-dynamic/);
  assert.match(content, /No real malware/i);
  assert.match(content, /docker pull node:22-bookworm-slim/);
});

test("status script inspects only the configured VM", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/status-sandbox-vm.sh"), "utf8");

  assert.match(content, /gcloud compute instances describe "\$\{vm_name\}"/);
  assert.doesNotMatch(content, /instances list/);
});

test("malware readiness script checks disposable VM constraints without creating resources", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/check-malware-readiness.sh"), "utf8");

  assert.match(content, /serviceAccounts/);
  assert.match(content, /purpose=sandbox/);
  assert.match(content, /status.*RUNNING/);
  assert.match(content, /docker --version/);
  assert.match(content, /packages\/cli\/dist\/index\.js/);
  assert.doesNotMatch(content, /compute instances create/);
  assert.doesNotMatch(content, /auth login/);
});

test("malicious sample runner requires exact opt-in, manifest input, readiness, and cleanup guidance", async () => {
  const content = await readFile(path.join(repoRoot, "scripts/gcloud/run-malicious-samples-on-vm.sh"), "utf8");

  assert.match(content, /UNSUS_REAL_MALWARE_TESTING/);
  assert.match(content, /I_ACCEPT_REAL_MALWARE_RISK/);
  assert.match(content, /UNSUS_MALWARE_SAMPLE_MANIFEST/);
  assert.match(content, /check-malware-readiness\.sh/);
  assert.match(content, /--allow-remote-dynamic/);
  assert.match(content, /docker pull node:22-bookworm-slim/);
  assert.match(content, /destroy-sandbox-vm\.sh/);
  assert.match(content, /tar -czf \/tmp\/unsus-gcloud-malware-lab-logs\.tar\.gz/);
  assert.doesNotMatch(content, /npm install <random package>/);
  assert.doesNotMatch(content, /gcloud auth login/);
});

test("malware lab docs define the real-payload safety gate", async () => {
  const docs = [
    await readFile(path.join(repoRoot, "docs/malicious-payload-testing.md"), "utf8"),
    await readFile(path.join(repoRoot, "docs/gcloud-sandbox.md"), "utf8"),
    await readFile(path.join(repoRoot, "scripts/gcloud/README.md"), "utf8")
  ].join("\n");

  assert.match(docs, /real malicious/i);
  assert.match(docs, /UNSUS_REAL_MALWARE_TESTING=I_ACCEPT_REAL_MALWARE_RISK/);
  assert.match(docs, /UNSUS_MALWARE_SAMPLE_MANIFEST/);
  assert.match(docs, /destroy-sandbox-vm\.sh/);
  assert.match(docs, /no host secrets/i);
  assert.match(docs, /not.*host/i);
});

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
