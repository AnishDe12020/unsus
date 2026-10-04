import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import type { Finding, FindingSeverity, ScanResult } from "../types.js";

// Static descriptions deliberately exclude matched source, script commands, and absolute paths.
const descriptions: Record<string, string> = {
  lifecycle_script: "The package declares a lifecycle script. Review it before enabling installation scripts.",
  suspicious_lifecycle_command: "A lifecycle script contains a command commonly used to fetch or execute code.",
  base64_like_metadata: "Package metadata contains a long encoded-looking value.",
  eval_call: "Source calls eval().",
  function_constructor: "Source constructs code dynamically with Function().",
  child_process_import: "Source imports child_process.",
  child_process_execution: "Source invokes an API bound to child_process.",
  dynamic_require: "Source calls require() with a non-literal argument.",
  base64_decode: "Source decodes base64 content.",
  charcode_chain: "Source constructs a string from a long character-code sequence.",
  network_api: "Source references a network API.",
  credential_file_access: "Source references credential-like local file paths.",
  process_env_access: "Source reads environment variables.",
  high_entropy_string: "Source contains a long high-entropy string that may be encoded data.",
  escape_chain: "Source contains a long hex or Unicode escape sequence.",
  url_literal: "Source contains a URL literal. This alone does not establish malicious behavior.",
  ip_literal: "Source contains an IP address literal.",
  wallet_like_literal: "Source contains a cryptocurrency-wallet-like string.",
  executable_extension: "The package contains a file with an executable-looking extension.",
  binary_header: "The package contains a file with an executable binary header.",
  incomplete_coverage: "Some text files exceed the read limit or contain binary data and were not fully analyzed."
};
const levels: Record<FindingSeverity, "note" | "warning" | "error"> = {
  info: "note", warning: "warning", danger: "error", critical: "error"
};
const version: string = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")).version;

/** A URI relative to the scanned package, never to the user's machine or temporary extraction directory. */
function relativeUri(file: string | undefined): string | undefined {
  if (!file || /[\\:\u0000-\u001f\u007f]/.test(file)) return undefined;
  const components = file.split("/");
  if (components.some(part => !part || part === "." || part === "..")) return undefined;
  try { return components.map(part => encodeURIComponent(part)).join("/"); }
  catch { return undefined; } // Invalid Unicode must not turn report generation into a scan failure.
}

function ruleType(finding: Finding): string {
  return Object.hasOwn(descriptions, finding.type) ? finding.type : "other_static_finding";
}

/** SARIF 2.1.0 static results. Raw messages and snippets remain available in the separate JSON format. */
export function formatSarifReport(report: ScanResult): string {
  if (report.sandbox) throw new Error("SARIF reporting supports static scans only; omit --dynamic.");
  const types = [...new Set(report.findings.map(ruleType))].sort();
  const rules = types.map(type => ({
    id: `unsus.${type}`,
    shortDescription: { text: type.replaceAll("_", " ") },
    fullDescription: { text: descriptions[type] ?? "The static analyzer reported a finding requiring review." },
    helpUri: "https://github.com/AnishDe12020/unsus#analysis-and-limits",
    properties: { tags: ["security", "heuristic", "direct-package"] }
  }));
  const exitCode = report.decision === "block" ? 2 : report.decision === "warn" ? 1 : 0;
  const coverage = {
    scope: "direct-package",
    dependenciesAnalyzed: false,
    complete: report.coverage?.complete ?? false,
    ...(report.coverage ? {
      files: report.coverage.files,
      textFilesAnalyzed: report.coverage.textFilesAnalyzed,
      omittedTextFileCount: report.coverage.omittedTextFiles.length,
      omittedTextFiles: report.coverage.omittedTextFiles.map(relativeUri).filter(uri => uri !== undefined)
    } : {}),
    limitations: ["Heuristic findings do not establish safety.", "Dependencies and runtime behavior are not analyzed.", "Locations are relative to the scanned package, not necessarily the CI checkout."]
  };
  const results = report.findings.map(finding => {
    const type = ruleType(finding);
    const uri = relativeUri(finding.file);
    const line = Number.isSafeInteger(finding.line) && finding.line! > 0 ? finding.line : undefined;
    return {
      ruleId: `unsus.${type}`,
      ruleIndex: types.indexOf(type),
      level: levels[finding.severity] ?? "warning",
      message: { text: descriptions[type] ?? "The static analyzer reported a finding requiring review." },
      ...(uri ? { locations: [{ physicalLocation: {
        artifactLocation: { uri, uriBaseId: "%PACKAGE_ROOT%" },
        ...(line !== undefined ? { region: { startLine: line } } : {})
      } }] } : {}),
      ...(uri && finding.code ? { partialFingerprints: {
        "unsus/matchedEvidence/v1": createHash("sha256").update(type).update("\0").update(finding.code).digest("hex")
      } } : {}),
      properties: {
        ...(Number.isFinite(finding.confidence) ? { confidence: finding.confidence } : {}),
        ...(finding.file && !uri ? { locationOmitted: true } : {})
      }
    };
  });
  return JSON.stringify({
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "unsus", version, informationUri: "https://github.com/AnishDe12020/unsus", rules } },
      invocations: [{ executionSuccessful: true, exitCode, properties: { analysisMode: "static", coverage } }],
      results,
      properties: {
        package: {
          name: /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(report.package.name) ? report.package.name : "(anonymous)",
          version: /^[0-9A-Za-z.+-]+$/.test(report.package.version) ? report.package.version : "(unspecified)"
        },
        decision: report.decision,
        riskLevel: report.riskLevel,
        riskScore: report.riskScore,
        coverage
      }
    }]
  }, null, 2) + "\n";
}
