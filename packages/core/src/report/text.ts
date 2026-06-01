import type { Finding, ScanResult, VersionDiffResult } from "../types.js";

export function formatScanText(result: ScanResult): string {
  const lines = [
    "UNSUS PACKAGE FIREWALL",
    "",
    `Package: ${result.package.name}@${result.package.version}`,
    `Decision: ${result.decision.toUpperCase()}`,
    `Risk: ${result.riskLevel.toUpperCase()} ${result.riskScore.toFixed(1)}/10`,
    "",
    "Why:"
  ];

  lines.push(...formatFindings(result.findings));
  lines.push("", "Recommendation:", ...recommendations(result));
  return `${lines.join("\n")}\n`;
}

export function formatDiffText(result: VersionDiffResult): string {
  const lines = [
    "UNSUS VERSION DIFF",
    "",
    `From: ${result.from.name}@${result.from.version}`,
    `To: ${result.to.name}@${result.to.version}`,
    "",
    `Added files: ${result.addedFiles.length}`,
    `Removed files: ${result.removedFiles.length}`,
    `Changed files: ${result.changedFiles.length}`,
    "",
    "Findings:"
  ];

  lines.push(...formatFindings(result.findings));
  return `${lines.join("\n")}\n`;
}

function formatFindings(findings: Finding[]): string[] {
  if (findings.length === 0) {
    return ["1. No risky behavior detected."];
  }

  return findings.slice(0, 20).map((finding, index) => {
    const location = finding.file ? ` (${finding.file}${finding.line ? `:${finding.line}` : ""})` : "";
    return `${index + 1}. ${finding.title}${location}: ${finding.message}`;
  });
}

function recommendations(result: ScanResult): string[] {
  if (result.decision === "block") {
    return [
      "- Do not install this version unless you have manually verified the findings.",
      "- If this was already installed, review package scripts and rotate exposed credentials if needed."
    ];
  }

  if (result.decision === "warn") {
    return ["- Review findings before installing.", "- Prefer a pinned known-good version in CI."];
  }

  return ["- Install may proceed under the current policy."];
}
