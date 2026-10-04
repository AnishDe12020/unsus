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

  if (result.coverage) {
    lines.splice(6, 0, `Coverage: direct package only; ${result.coverage.textFilesAnalyzed} text files analyzed; ${result.coverage.omittedTextFiles.length} omitted. Dependencies not scanned.`, "Heuristic findings do not establish package safety.");
  }
  lines.push(...formatFindings(result.findings));
  if (result.sandbox) {
    lines.push("", "Sandbox timeline:", ...formatSandboxTimeline(result));
  }
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
    return ["1. No matching risk signals found in analyzed files."];
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

function formatSandboxTimeline(result: ScanResult): string[] {
  const sandbox = result.sandbox;
  if (!sandbox) {
    return [];
  }

  const lines = [
    `- enabled: ${sandbox.enabled}`,
    `- timed out: ${sandbox.timedOut}`
  ];

  if (typeof sandbox.exitCode === "number") {
    lines.push(`- exit code: ${sandbox.exitCode}`);
  }

  if (sandbox.timeline.length === 0) {
    lines.push("- no sandbox events recorded");
    return lines;
  }

  return [
    ...lines,
    ...sandbox.timeline.map((event) => `- ${event.timeMs}ms: ${event.message}`)
  ];
}
