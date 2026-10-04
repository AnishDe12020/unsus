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
  const hasNetworkBehavior = types.has("network_api");
  const denseSourceObfuscation = detectDenseSourceObfuscation(findings);
  const hasObfuscationBehavior = ["base64_decode", "charcode_chain", "escape_chain"].some(type => types.has(type)) || denseSourceObfuscation.blockAlone;
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

  if (hasObfuscationBehavior && categories.has("dynamic_code_execution")) {
    score = Math.max(score, 8.0);
    chainTriggered = true;
  }

  if (hasObfuscationBehavior && (categories.has("code_execution") || hasNetworkBehavior)) {
    score = Math.max(score, 9.0);
    chainTriggered = true;
  }

  if (
    denseSourceObfuscation.blockAlone ||
    (categories.has("install_time_execution") && denseSourceObfuscation.installTimeChain)
  ) {
    score = Math.max(score, categories.has("install_time_execution") ? 8.2 : 7.2);
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

  if (!chainTriggered && !findings.some(finding => finding.severity === "critical")) score = Math.min(score, 6.8);
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

interface DenseSourceObfuscation {
  blockAlone: boolean;
  installTimeChain: boolean;
}

function detectDenseSourceObfuscation(findings: Finding[]): DenseSourceObfuscation {
  const highEntropySourceFindings = findings.filter((finding) => {
    if (finding.type !== "high_entropy_string" || !finding.file) {
      return false;
    }

    if (!/\.[cm]?[jt]sx?$/i.test(finding.file) || /\.d\.[cm]?ts$/i.test(finding.file) || isLowSignalMetadataOrDocPath(finding.file)) {
      return false;
    }

    return true;
  });

  if (highEntropySourceFindings.length < 5) {
    return { blockAlone: false, installTimeChain: false };
  }

  const hasLargePayload = highEntropySourceFindings.some((finding) => {
    const length = numericEvidence(finding, "length");
    const entropy = numericEvidence(finding, "entropy");
    return length >= 500 && entropy >= 5;
  });

  const totalLength = highEntropySourceFindings.reduce((sum, finding) => sum + numericEvidence(finding, "length"), 0);
  const averageEntropy =
    highEntropySourceFindings.reduce((sum, finding) => sum + numericEvidence(finding, "entropy"), 0) /
    highEntropySourceFindings.length;
  const hasHighEntropyAggregate = totalLength >= 1000 && averageEntropy >= 5;
  const hasLargeInstallTimeAggregate =
    highEntropySourceFindings.length >= 20 && totalLength >= 2000 && averageEntropy >= 4.5;

  return {
    blockAlone: hasLargePayload || hasHighEntropyAggregate,
    installTimeChain: hasLargePayload || hasHighEntropyAggregate || hasLargeInstallTimeAggregate
  };
}

function isLowSignalMetadataOrDocPath(filePath: string): boolean {
  return (
    /^package\.json$/i.test(filePath) ||
    /(^|\/)(readme|license|licence|changelog|changes|history|notice)(\.|$)/i.test(filePath)
  );
}

function numericEvidence(finding: Finding, key: string): number {
  const value = finding.evidence?.[key];
  if (typeof value === "number") {
    return value;
  }

  if (typeof value === "string" && value.trim() !== "") {
    return Number(value);
  }

  return 0;
}
