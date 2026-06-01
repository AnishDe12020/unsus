import assert from "node:assert/strict";
import { test } from "node:test";

import type { Finding } from "../types.js";
import { calculateRiskScore, decisionFromPolicy, defaultPolicy, riskLevelFromScore } from "./score.js";

function finding(category: Finding["category"], type: string, severity: Finding["severity"] = "warning"): Finding {
  return {
    id: `${category}:${type}`,
    category,
    type,
    severity,
    title: type,
    message: type,
    confidence: 0.9
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
