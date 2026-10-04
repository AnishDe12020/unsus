import assert from "node:assert/strict";
import { test } from "node:test";

import type { Finding } from "../types.js";
import { calculateRiskScore, decisionFromPolicy, defaultPolicy, riskLevelFromScore } from "./score.js";

function finding(
  category: Finding["category"],
  type: string,
  severity: Finding["severity"] = "warning",
  extra: Partial<Finding> = {}
): Finding {
  return {
    id: `${category}:${type}`,
    category,
    type,
    severity,
    title: type,
    message: type,
    confidence: 0.9,
    ...extra
  };
}

test("scoring raises install script plus network to high", () => {
  const score = calculateRiskScore([
    finding("install_time_execution", "lifecycle_script"),
    finding("network_access", "network_api")
  ]);

  assert.equal(riskLevelFromScore(score), "high");
});

test("scoring raises install script plus env plus network to critical", () => {
  const score = calculateRiskScore([
    finding("install_time_execution", "lifecycle_script"),
    finding("credential_access", "process_env_access"),
    finding("network_access", "network_api")
  ]);

  assert.equal(riskLevelFromScore(score), "critical");
});

test("policy blocks high and critical results by default", () => {
  assert.equal(decisionFromPolicy("high", defaultPolicy), "block");
  assert.equal(decisionFromPolicy("medium", defaultPolicy), "warn");
  assert.equal(decisionFromPolicy("low", defaultPolicy), "allow");
});

test("scoring does not block packages for accumulated documentation URLs and entropy alone", () => {
  const noisyFindings = Array.from({ length: 30 }, (_, index) =>
    finding(index % 2 === 0 ? "network_access" : "obfuscation", index % 2 === 0 ? "url_literal" : "high_entropy_string")
  );

  const score = calculateRiskScore(noisyFindings);

  assert.equal(riskLevelFromScore(score), "low");
  assert.equal(decisionFromPolicy(riskLevelFromScore(score), defaultPolicy), "allow");
});

test("scoring blocks dense source obfuscation with a large high-entropy payload", () => {
  const obfuscationFindings = Array.from({ length: 8 }, (_, index) =>
    finding("obfuscation", "high_entropy_string", "warning", {
      file: "lib/commonjs/index.js",
      evidence: { length: index === 0 ? 1251 : 120, entropy: index === 0 ? 5.49 : 4.8 }
    })
  );

  const score = calculateRiskScore(obfuscationFindings);

  assert.ok(["high", "critical"].includes(riskLevelFromScore(score)));
  assert.equal(decisionFromPolicy(riskLevelFromScore(score), defaultPolicy), "block");
});

test("scoring blocks install-time execution combined with dense source obfuscation", () => {
  const score = calculateRiskScore([
    finding("install_time_execution", "lifecycle_script"),
    ...Array.from({ length: 5 }, () =>
      finding("obfuscation", "high_entropy_string", "warning", {
        file: "lib/index.js",
        evidence: { length: 300, entropy: 5.1 }
      })
    )
  ]);

  assert.ok(["high", "critical"].includes(riskLevelFromScore(score)));
  assert.equal(decisionFromPolicy(riskLevelFromScore(score), defaultPolicy), "block");
});

test("scoring blocks install-time execution combined with large aggregate source entropy", () => {
  const score = calculateRiskScore([
    finding("install_time_execution", "lifecycle_script"),
    ...Array.from({ length: 25 }, () =>
      finding("obfuscation", "high_entropy_string", "warning", {
        file: "lib/index.js",
        evidence: { length: 150, entropy: 4.8 }
      })
    )
  ]);

  assert.ok(["high", "critical"].includes(riskLevelFromScore(score)));
  assert.equal(decisionFromPolicy(riskLevelFromScore(score), defaultPolicy), "block");
});

test("unrelated documentation entropy and address literals do not turn an isolated capability into a blocking chain", () => {
  const findings = [finding("code_execution", "child_process_import", "danger"), ...Array.from({ length: 40 }, () => finding("obfuscation", "high_entropy_string", "warning", { file: "README.md", evidence: { length: 90, entropy: 4.5 } })), finding("network_access", "ip_literal", "info")];
  assert.equal(decisionFromPolicy(riskLevelFromScore(calculateRiskScore(findings)), defaultPolicy), "warn");
});
