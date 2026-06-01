import assert from "node:assert/strict";
import { test } from "node:test";

import type { ScanResult } from "../types.js";
import { formatScanText } from "./text.js";

test("formatScanText includes sandbox timeline when sandbox result is present", () => {
  const report: ScanResult = {
    package: {
      name: "fixture",
      version: "1.0.0"
    },
    riskScore: 1,
    riskLevel: "low",
    decision: "allow",
    findings: [],
    summary: "ok",
    generatedAt: "2026-06-01T00:00:00.000Z",
    sandbox: {
      enabled: true,
      timedOut: false,
      exitCode: 0,
      findings: [],
      timeline: [
        { timeMs: 0, type: "sandbox_started", message: "sandbox started" },
        { timeMs: 21, type: "lifecycle_script_detected", message: "detected postinstall script: node postinstall.js" },
        { timeMs: 190, type: "file_created", message: "file created inside workspace: build-marker.txt" }
      ]
    }
  };

  const output = formatScanText(report);

  assert.match(output, /Sandbox timeline:/);
  assert.match(output, /0ms: sandbox started/);
  assert.match(output, /21ms: detected postinstall script: node postinstall.js/);
  assert.match(output, /190ms: file created inside workspace: build-marker.txt/);
});
