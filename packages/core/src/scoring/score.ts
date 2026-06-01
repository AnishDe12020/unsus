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

  if (categories.has("install_time_execution") && categories.has("network_access")) {
    score = Math.max(score, 7.4);
  }

  if (categories.has("install_time_execution") && categories.has("code_execution")) {
    score = Math.max(score, 7.6);
  }

  if (
    categories.has("install_time_execution") &&
    categories.has("credential_access") &&
    categories.has("network_access")
  ) {
    score = Math.max(score, 9.2);
  }

  if (categories.has("obfuscation") && categories.has("dynamic_code_execution")) {
    score = Math.max(score, 8.0);
  }

  if (categories.has("obfuscation") && (categories.has("code_execution") || categories.has("network_access"))) {
    score = Math.max(score, 9.0);
  }

  if (types.has("credential_file_access") && categories.has("network_access")) {
    score = Math.max(score, 9.1);
  }

  if (types.has("new_dependency_with_lifecycle_script")) {
    score = Math.max(score, 7.5);
  }

  if (categories.has("typosquat") && categories.has("install_time_execution")) {
    score = Math.max(score, 7.8);
  }

  if (categories.has("binary_payload") && categories.has("install_time_execution")) {
    score = Math.max(score, 9.3);
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
