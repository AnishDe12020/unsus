import type { ExtractedPackage, Finding } from "../types.js";
import { createFinding, lineForOffset } from "./finding.js";

const URL_PATTERN = /https?:\/\/[^\s"'`<>]+/g;
const IP_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const WALLET_LIKE_PATTERN = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b/g;

export function analyzeIocs(pkg: ExtractedPackage): Finding[] {
  const findings: Finding[] = [];

  for (const file of pkg.files) {
    if (!file.content) {
      continue;
    }

    for (const match of file.content.matchAll(URL_PATTERN)) {
      findings.push(
        createFinding({
          category: "network_access",
          type: "url_literal",
          severity: "warning",
          title: "Hardcoded URL",
          message: "Source contains a hardcoded URL. This is informational unless combined with risky install-time behavior.",
          file: file.path,
          line: lineForOffset(file.content, match.index ?? 0),
          code: match[0],
          confidence: 0.8
        })
      );
    }

    for (const match of file.content.matchAll(IP_PATTERN)) {
      findings.push(
        createFinding({
          category: "network_access",
          type: "ip_literal",
          severity: "info",
          title: "IP literal",
          message: "Source contains an IP address literal.",
          file: file.path,
          line: lineForOffset(file.content, match.index ?? 0),
          code: match[0],
          confidence: 0.65
        })
      );
    }

    for (const match of file.content.matchAll(WALLET_LIKE_PATTERN)) {
      findings.push(
        createFinding({
          category: "threat_intel",
          type: "wallet_like_literal",
          severity: "info",
          title: "Wallet-like literal",
          message: "Source contains a cryptocurrency-wallet-like string.",
          file: file.path,
          line: lineForOffset(file.content, match.index ?? 0),
          code: match[0],
          confidence: 0.5
        })
      );
    }
  }

  return findings;
}
