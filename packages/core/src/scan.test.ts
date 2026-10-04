import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import type { DynamicSandboxRunner } from "./types.js";
import { scanTarget } from "./scan.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("dynamic scan keeps benign build script below critical risk", async () => {
  const runner: DynamicSandboxRunner = async () => ({
    enabled: true,
    timedOut: false,
    exitCode: 0,
    timeline: [
      { timeMs: 0, type: "sandbox_started", message: "sandbox started" },
      { timeMs: 10, type: "file_created", message: "file created inside workspace: build-marker.txt" }
    ],
    findings: []
  });

  const result = await scanTarget(path.join(repoRoot, "fixtures/benign/install-script-build-package"), {
    dynamic: true,
    dynamicRunner: runner
  });

  assert.equal(result.sandbox?.enabled, true);
  assert.notEqual(result.riskLevel, "critical");
  assert.equal(result.decision, "allow");
});

test("dynamic scan includes sandbox findings and still blocks suspicious install behavior", async () => {
  const runner: DynamicSandboxRunner = async () => ({
    enabled: true,
    timedOut: false,
    exitCode: 0,
    timeline: [
      { timeMs: 0, type: "sandbox_started", message: "sandbox started" },
      { timeMs: 20, type: "network_detection_unsupported", message: "network-attempt detection is unsupported" }
    ],
    findings: [
      {
        id: "sandbox.network_detection_unsupported",
        category: "sandbox_behavior",
        type: "network_detection_unsupported",
        severity: "info",
        title: "Network attempt detection unsupported",
        message: "This sandbox version does not yet trace attempted network syscalls.",
        confidence: 1
      }
    ]
  });

  const result = await scanTarget(path.join(repoRoot, "fixtures/suspicious/postinstall-env-network"), {
    dynamic: true,
    dynamicRunner: runner
  });

  assert.equal(result.sandbox?.enabled, true);
  assert.equal(result.decision, "block");
  assert.ok(result.findings.some((finding) => finding.type === "network_detection_unsupported"));
});

test("dynamic results preserve strict fail-on policy when text coverage is incomplete", async () => {
  const fs = await import("node:fs/promises");
  const os = await import("node:os");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-test-coverage-"));
  try {
    await fs.writeFile(path.join(root, "package.json"), '{"name":"fixture","version":"1.0.0"}');
    await fs.writeFile(path.join(root, "large.js"), "a".repeat(300_000));
    const result = await scanTarget(root, { dynamic: true, failOn: "safe", dynamicRunner: async () => ({ enabled: true, timedOut: false, timeline: [], findings: [] }) });
    assert.equal(result.decision, "block");
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
