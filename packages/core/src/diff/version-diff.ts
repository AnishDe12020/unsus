import { createHash } from "node:crypto";

import { analyzePackage } from "../scan.js";
import type { ExtractedPackage, Finding, PackageFile, VersionDiffResult } from "../types.js";
import { createFinding } from "../analyzers/finding.js";
import { extractLocalPackage } from "../extract/local.js";
import { resolveNpmPackage } from "../resolver/npm.js";

export async function diffTargets(toTarget: string, againstTarget: string): Promise<VersionDiffResult> {
  const [to, from] = await Promise.all([resolveDiffTarget(toTarget), resolveDiffTarget(againstTarget)]);
  try {
    return compareExtractedPackages(from, to);
  } finally {
    await to.cleanup?.();
    await from.cleanup?.();
  }
}

export function compareExtractedPackages(from: ExtractedPackage, to: ExtractedPackage): VersionDiffResult {
  const fromFiles = new Map(from.files.map((file) => [file.path, file]));
  const toFiles = new Map(to.files.map((file) => [file.path, file]));
  const addedFiles = [...toFiles.keys()].filter((filePath) => !fromFiles.has(filePath)).sort();
  const removedFiles = [...fromFiles.keys()].filter((filePath) => !toFiles.has(filePath)).sort();
  const changedFiles = [...toFiles.entries()]
    .filter(([filePath, file]) => fromFiles.has(filePath) && fileHash(fromFiles.get(filePath)!) !== fileHash(file))
    .map(([filePath]) => filePath)
    .sort();
  const packageJsonChanges = diffPackageJson(from.packageJson, to.packageJson);
  const findings = diffFindings(from, to, addedFiles, toFiles);

  return {
    from: from.identity,
    to: to.identity,
    findings,
    changedFiles,
    addedFiles,
    removedFiles,
    packageJsonChanges
  };
}

function diffFindings(
  from: ExtractedPackage,
  to: ExtractedPackage,
  addedFiles: string[],
  toFiles: Map<string, PackageFile>
): Finding[] {
  const findings: Finding[] = [];
  const fromScripts = scripts(from.packageJson);
  const toScripts = scripts(to.packageJson);

  for (const [name, command] of Object.entries(toScripts)) {
    if (!fromScripts[name]) {
      findings.push(
        createFinding({
          category: "version_diff_anomaly",
          type: "new_lifecycle_script",
          severity: "danger",
          title: `New lifecycle script: ${name}`,
          message: `New version adds ${name} script: ${command}`,
          file: "package.json",
          code: command,
          evidence: { script: name },
          confidence: 0.95
        })
      );
    } else if (fromScripts[name] !== command) {
      findings.push(
        createFinding({
          category: "version_diff_anomaly",
          type: "changed_lifecycle_script",
          severity: "danger",
          title: `Changed lifecycle script: ${name}`,
          message: `New version changes ${name} script.`,
          file: "package.json",
          evidence: { script: name, from: fromScripts[name], to: command },
          confidence: 0.9
        })
      );
    }
  }

  const fromDeps = dependencies(from.packageJson);
  const toDeps = dependencies(to.packageJson);
  for (const [name, version] of Object.entries(toDeps)) {
    if (!fromDeps[name]) {
      findings.push(
        createFinding({
          category: "version_diff_anomaly",
          type: "new_dependency",
          severity: "warning",
          title: `New dependency: ${name}`,
          message: `New version adds dependency ${name}@${version}.`,
          file: "package.json",
          evidence: { dependency: name, version },
          confidence: 0.85
        })
      );
    }
  }

  const addedSet = new Set(addedFiles);
  const addedPackage = {
    ...to,
    files: to.files.filter((file) => addedSet.has(file.path))
  };
  for (const finding of analyzePackage(addedPackage)) {
    findings.push({
      ...finding,
      type: finding.category === "binary_payload" ? "new_binary_file" : "new_suspicious_source_file",
      category: "version_diff_anomaly",
      title: `New file finding: ${finding.title}`,
      message: `Added file ${finding.file ?? "unknown"} has finding: ${finding.message}`
    });
  }

  for (const filePath of addedFiles) {
    const file = toFiles.get(filePath);
    if (file?.kind === "binary") {
      findings.push(
        createFinding({
          category: "version_diff_anomaly",
          type: "new_binary_file",
          severity: "danger",
          title: "New binary file",
          message: `New version adds binary file ${filePath}.`,
          file: filePath,
          confidence: 0.85
        })
      );
    }
  }

  return findings;
}

function diffPackageJson(from: Record<string, unknown>, to: Record<string, unknown>): Record<string, unknown> {
  const changes: Record<string, unknown> = {};
  for (const key of new Set([...Object.keys(from), ...Object.keys(to)])) {
    if (JSON.stringify(from[key]) !== JSON.stringify(to[key])) {
      changes[key] = { from: from[key] ?? null, to: to[key] ?? null };
    }
  }
  return changes;
}

function scripts(packageJson: Record<string, unknown>): Record<string, string> {
  const value = packageJson.scripts;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string")
  );
}

function dependencies(packageJson: Record<string, unknown>): Record<string, string> {
  const sections = ["dependencies", "optionalDependencies", "peerDependencies"];
  const result: Record<string, string> = {};

  for (const section of sections) {
    const value = packageJson[section];
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      for (const [name, version] of Object.entries(value)) {
        if (typeof version === "string") {
          result[name] = version;
        }
      }
    }
  }

  return result;
}

async function resolveDiffTarget(target: string): Promise<ExtractedPackage> {
  try {
    return await extractLocalPackage(target);
  } catch {
    if (looksLikeLocalPath(target)) {
      throw new Error(`Local package path does not exist or is not a package directory: ${target}`);
    }

    return resolveNpmPackage(target);
  }
}

function looksLikeLocalPath(target: string): boolean {
  return target.startsWith(".") || target.startsWith("/") || target.includes("/") || target.includes("\\");
}

function fileHash(file: PackageFile): string {
  return createHash("sha256")
    .update(file.content ?? "")
    .update(Buffer.from(file.headerBytes ?? new Uint8Array()))
    .update(String(file.size))
    .digest("hex");
}
