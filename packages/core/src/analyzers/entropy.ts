import type { ExtractedPackage, Finding } from "../types.js";
import { sourceContext } from "./source-context.js";
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

    const context = file.kind === "source" ? sourceContext(file) : undefined;
    const fallbackOffset = context ? context.unparsedOffset : 0;
    const literals = [
      ...(context?.strings ?? []),
      ...(fallbackOffset !== undefined ? Array.from(file.content.slice(fallbackOffset).matchAll(STRING_LITERAL), match => ({ value: match[2] ?? "", start: fallbackOffset + (match.index ?? 0) })) : [])
    ];
    for (const literal of literals) {
      const value = literal.value;
      if (value.length >= 40 && shannonEntropy(value) >= 4.2) {
        const dataShape = file.kind === "source" ? tableShape(value) : undefined;
        findings.push(
          createFinding({
            category: "obfuscation",
            type: "high_entropy_string",
            severity: "warning",
            title: "High-entropy string",
            message: "Source contains a long high-entropy string that may be encoded or obfuscated data.",
            file: file.path,
            line: lineForOffset(file.content, literal.start),
            code: value.slice(0, 96),
            evidence: { length: value.length, entropy: Number(shannonEntropy(value).toFixed(2)),
              ...(dataShape ? { dataShape } : {}) },
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

/** Shape evidence only, never a declaration that the value or its consumer is safe. */
function tableShape(value: string): "unicode_ranges" | "word_table" | undefined {
  if (value.length >= 128 && /^[^\x00-\x7f-]+(?:-[^\x00-\x7f-]+)+$/u.test(value)) {
    const chars = [...value];
    let ranges = 0;
    const valid = chars.every((char, i) => {
      if (char !== "-") return true;
      ranges++;
      return chars[i - 1]!.codePointAt(0)! < chars[i + 1]!.codePointAt(0)!;
    });
    if (valid && ranges >= 8) return "unicode_ranges";
  }
  const words = value.trim().split(/\s+/);
  // Every token must fit: adding a short word prefix cannot exempt a long payload.
  if (words.length >= 8 && new Set(words).size >= 8 && words.every(word => /^[A-Za-z][A-Za-z_]{1,31}$/.test(word))) return "word_table";
  return undefined;
}
