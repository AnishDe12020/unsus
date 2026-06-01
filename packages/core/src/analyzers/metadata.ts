import type { ExtractedPackage, Finding } from "../types.js";
import { createFinding } from "./finding.js";

const LIFECYCLE_SCRIPTS = new Set(["preinstall", "install", "postinstall", "preuninstall", "prepare"]);
const SUSPICIOUS_SCRIPT_FRAGMENTS = [
  "curl",
  "wget",
  "bash -c",
  "sh -c",
  "powershell",
  "Invoke-WebRequest",
  "node -e",
  "EncodedCommand",
  "-enc"
];

export function analyzeMetadata(pkg: ExtractedPackage): Finding[] {
  const findings: Finding[] = [];
  const scripts = objectValue(pkg.packageJson.scripts);

  for (const [name, value] of Object.entries(scripts)) {
    if (typeof value !== "string" || !LIFECYCLE_SCRIPTS.has(name)) {
      continue;
    }

    findings.push(
      createFinding({
        category: "install_time_execution",
        type: "lifecycle_script",
        severity: name === "prepare" ? "warning" : "danger",
        title: `Lifecycle script: ${name}`,
        message: `package.json contains ${name} script: ${value}`,
        file: "package.json",
        code: value,
        evidence: { script: name, command: value },
        confidence: 0.95
      })
    );

    for (const fragment of SUSPICIOUS_SCRIPT_FRAGMENTS) {
      if (value.toLowerCase().includes(fragment.toLowerCase())) {
        findings.push(
          createFinding({
            category: "install_time_execution",
            type: "suspicious_lifecycle_command",
            severity: "danger",
            title: `Suspicious lifecycle command fragment: ${fragment}`,
            message: `${name} script contains suspicious command fragment: ${fragment}`,
            file: "package.json",
            code: value,
            evidence: { script: name, fragment },
            confidence: 0.9
          })
        );
      }
    }
  }

  for (const [key, value] of Object.entries(pkg.packageJson)) {
    if (typeof value === "string" && looksBase64Like(value) && !["version", "name"].includes(key)) {
      findings.push(
        createFinding({
          category: "metadata_anomaly",
          type: "base64_like_metadata",
          severity: "warning",
          title: "Base64-looking metadata field",
          message: `package.json field ${key} contains a long base64-looking value.`,
          file: "package.json",
          evidence: { field: key },
          confidence: 0.65
        })
      );
    }
  }

  return findings;
}

function objectValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function looksBase64Like(value: string): boolean {
  return value.length >= 48 && /^[A-Za-z0-9+/=_-]+$/.test(value);
}
