import type { Finding, RiskLevel, RiskPolicy } from "../types.js";
import { decisionFromPolicy, defaultPolicy } from "./policy.js";

export { decisionFromPolicy, defaultPolicy };

export function calculateRiskScore(findings: Finding[]): number {
  if (findings.length === 0) {
    return 0;
  }

  let score = 0;
  for (const finding of findings) {
    score += severityPoints(finding.severity) * finding.confidence;
  }

  const categories = new Set(findings.map((finding) => finding.category));
  const types = new Set(findings.map((finding) => finding.type));
  const hasNetworkBehavior = types.has("network_api") || types.has("ip_literal");
  const hasOnlyLowSignalNoise = findings.every((finding) =>
    ["url_literal", "high_entropy_string", "network_detection_unsupported", "wallet_like_literal"].includes(finding.type)
  );
  let chainTriggered = false;

  if (categories.has("install_time_execution") && hasNetworkBehavior) {
    score = Math.max(score, 7.4);
    chainTriggered = true;
  }

  if (categories.has("install_time_execution") && categories.has("code_execution")) {
    score = Math.max(score, 7.6);
    chainTriggered = true;
  }

  if (
    categories.has("install_time_execution") &&
    categories.has("credential_access") &&
    hasNetworkBehavior
  ) {
    score = Math.max(score, 9.2);
    chainTriggered = true;
  }

  if (categories.has("obfuscation") && categories.has("dynamic_code_execution")) {
    score = Math.max(score, 8.0);
    chainTriggered = true;
  }

  if (categories.has("obfuscation") && (categories.has("code_execution") || hasNetworkBehavior)) {
    score = Math.max(score, 9.0);
    chainTriggered = true;
  }

  if (types.has("credential_file_access") && hasNetworkBehavior) {
    score = Math.max(score, 9.1);
    chainTriggered = true;
  }

  if (types.has("new_dependency_with_lifecycle_script")) {
    score = Math.max(score, 7.5);
    chainTriggered = true;
  }

  if (categories.has("typosquat") && categories.has("install_time_execution")) {
    score = Math.max(score, 7.8);
    chainTriggered = true;
  }

  if (categories.has("binary_payload") && categories.has("install_time_execution")) {
    score = Math.max(score, 9.3);
    chainTriggered = true;
  }

  if (!chainTriggered && hasOnlyLowSignalNoise) {
    score = Math.min(score, 2.5);
  } else if (!chainTriggered && !findings.some((finding) => finding.severity === "danger" || finding.severity === "critical")) {
    score = Math.min(score, 4.0);
  }

  return Math.min(10, Number(score.toFixed(1)));
}

export function riskLevelFromScore(score: number): RiskLevel {
  if (score <= 0) {
    return "safe";
  }

  if (score < 3) {
    return "low";
  }

  if (score < 7) {
    return "medium";
  }

  if (score < 9) {
    return "high";
  }

  return "critical";
}

export function decisionForFindings(findings: Finding[], policy: RiskPolicy = defaultPolicy): ReturnType<typeof decisionFromPolicy> {
  return decisionFromPolicy(riskLevelFromScore(calculateRiskScore(findings)), policy);
}

function severityPoints(severity: Finding["severity"]): number {
  switch (severity) {
    case "info":
      return 0.4;
    case "warning":
      return 1.2;
    case "danger":
      return 2.4;
    case "critical":
      return 4.0;
  }
}
