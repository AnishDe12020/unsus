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
