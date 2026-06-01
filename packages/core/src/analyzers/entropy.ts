import type { ExtractedPackage, Finding } from "../types.js";
import { createFinding, lineForOffset } from "./finding.js";

const STRING_LITERAL = /(["'`])((?:\\.|(?!\1).){32,})\1/g;

export function analyzeEntropy(pkg: ExtractedPackage): Finding[] {
  const findings: Finding[] = [];

  for (const file of pkg.files) {
    if (!file.content || !(file.kind === "source" || file.kind === "json" || file.kind === "text")) {
      continue;
    }

    if (isLikelyMinifiedVendor(file.path, file.content)) {
      continue;
    }

    for (const match of file.content.matchAll(STRING_LITERAL)) {
      const value = match[2] ?? "";
      if (value.length >= 40 && shannonEntropy(value) >= 4.2) {
        findings.push(
          createFinding({
            category: "obfuscation",
            type: "high_entropy_string",
            severity: "warning",
            title: "High-entropy string",
            message: "Source contains a long high-entropy string that may be encoded or obfuscated data.",
            file: file.path,
            line: lineForOffset(file.content, match.index ?? 0),
            code: value.slice(0, 96),
            evidence: { length: value.length, entropy: Number(shannonEntropy(value).toFixed(2)) },
            confidence: 0.7
          })
        );
      }
    }

    for (const match of file.content.matchAll(/(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){12,}/g)) {
      findings.push(
        createFinding({
          category: "obfuscation",
          type: "escape_chain",
          severity: "warning",
          title: "Long escape sequence chain",
          message: "Source contains a long hex/unicode escape chain.",
          file: file.path,
          line: lineForOffset(file.content, match.index ?? 0),
          code: match[0].slice(0, 96),
          confidence: 0.75
        })
      );
    }
  }

  return findings;
}

export function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

function isLikelyMinifiedVendor(filePath: string, content: string): boolean {
  return /\.min\.[cm]?js$/i.test(filePath) || (content.length > 50000 && content.split("\n").length < 20);
}
