import { stat } from "node:fs/promises";

import { analyzeAst } from "./analyzers/ast.js";
import { analyzeBinary } from "./analyzers/binary.js";
import { analyzeEntropy } from "./analyzers/entropy.js";
import { analyzeIocs } from "./analyzers/ioc.js";
import { analyzeMetadata } from "./analyzers/metadata.js";
import { extractLocalPackage } from "./extract/local.js";
import { resolveNpmPackage } from "./resolver/npm.js";
import { calculateRiskScore, decisionFromPolicy, defaultPolicy, riskLevelFromScore } from "./scoring/score.js";
import type { ExtractedPackage, Finding, SandboxResult, ScanOptions, ScanResult } from "./types.js";

export async function scanTarget(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const extracted = await resolveTarget(target);
  try {
    const result = scanExtractedPackage(extracted, options);
    const sandbox = await maybeRunDynamicSandbox(extracted, options);
    if (!sandbox) {
      return result;
    }

    const findings = [...result.findings, ...sandbox.findings];
    const riskScore = calculateRiskScore(findings);
    const riskLevel = riskLevelFromScore(riskScore);
    return {
      ...result,
      findings,
      riskScore,
      riskLevel,
      decision: decisionFromPolicy(riskLevel, {
        ...defaultPolicy,
        ...(options.failOn ? { failOn: options.failOn } : {})
      }),
      sandbox,
      summary: summarizeFindings(findings)
    };
  } finally {
    await extracted.cleanup?.();
  }
}

export function scanExtractedPackage(pkg: ExtractedPackage, options: ScanOptions = {}): ScanResult {
  const findings = analyzePackage(pkg);
  const riskScore = calculateRiskScore(findings);
  const riskLevel = riskLevelFromScore(riskScore);
  const decision = decisionFromPolicy(riskLevel, {
    ...defaultPolicy,
    ...(options.failOn ? { failOn: options.failOn } : {})
  });

  return {
    package: pkg.identity,
    riskScore,
    riskLevel,
    decision,
    findings,
    summary: summarizeFindings(findings),
    generatedAt: new Date().toISOString(),
    ...(options.dynamic ? { sandbox: { enabled: false, timedOut: false, timeline: [], findings: [] } } : {})
  };
}

async function maybeRunDynamicSandbox(
  extracted: ExtractedPackage,
  options: ScanOptions
): Promise<SandboxResult | undefined> {
  if (!options.dynamic) {
    return undefined;
  }

  if (!extracted.isLocal && !options.allowRemoteDynamic) {
    return {
      enabled: false,
      timedOut: false,
      timeline: [
        {
          timeMs: 0,
          type: "dynamic_skipped",
          message: "Dynamic sandboxing is currently limited to local package directories."
        }
      ],
      findings: []
    };
  }

  if (!options.dynamicRunner) {
    return {
      enabled: false,
      timedOut: false,
      timeline: [
        {
          timeMs: 0,
          type: "dynamic_skipped",
          message: "No dynamic sandbox runner is configured."
        }
      ],
      findings: []
    };
  }

  return options.dynamicRunner(extracted);
}

export function analyzePackage(pkg: ExtractedPackage): Finding[] {
  return [
    ...analyzeMetadata(pkg),
    ...analyzeAst(pkg),
    ...analyzeEntropy(pkg),
    ...analyzeIocs(pkg),
    ...analyzeBinary(pkg)
  ];
}

async function resolveTarget(target: string): Promise<ExtractedPackage> {
  if (await isDirectory(target)) {
    return extractLocalPackage(target);
  }

  if (looksLikeLocalPath(target)) {
    throw new Error(`Local package path does not exist or is not a directory: ${target}`);
  }

  return resolveNpmPackage(target);
}

async function isDirectory(target: string): Promise<boolean> {
  try {
    return (await stat(target)).isDirectory();
  } catch {
    return false;
  }
}

function looksLikeLocalPath(target: string): boolean {
  return target.startsWith(".") || target.startsWith("/") || target.includes("/") || target.includes("\\");
}

function summarizeFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return "No risky package behavior detected.";
  }

  const criticalOrDanger = findings.filter((finding) => finding.severity === "critical" || finding.severity === "danger");
  if (criticalOrDanger.length > 0) {
    return `${criticalOrDanger.length} high-signal finding(s) detected across ${findings.length} total finding(s).`;
  }

  return `${findings.length} finding(s) detected. Review context before installing.`;
}
