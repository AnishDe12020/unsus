import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import semver from "semver";

import { extractLocalPackage } from "./extract/local.js";
import { scanExtractedPackage } from "./scan.js";
import type { Decision, RiskLevel, ScanResult } from "./types.js";

export interface ProjectOptions { includeDev?: boolean; maxPackages?: number; failOn?: RiskLevel }
export interface ProjectDependency {
  name: string;
  requested: string;
  sections: string[];
  status: "scanned" | "unresolved" | "omitted" | "failed";
  reason?: string;
  report?: ScanResult;
}
export interface ProjectResult {
  kind: "project";
  decision: Decision;
  exitCode: number;
  dependencies: ProjectDependency[];
  coverage: {
    scope: "declared-direct-dependencies"; source: "installed-node_modules";
    complete: boolean; declared: number; scanned: number; unresolved: number; omitted: number; failed: number;
    maxPackages: number; includeDev: boolean; lockfileVerified: false; transitiveDependenciesAnalyzed: false;
    limitations: string[];
  };
}

/** Offline inspection of installed direct dependencies; never resolves or installs package code. */
export async function scanProject(directory: string, options: ProjectOptions = {}): Promise<ProjectResult> {
  const maxPackages = options.maxPackages ?? 20;
  if (!Number.isInteger(maxPackages) || maxPackages < 1 || maxPackages > 100) throw new Error("--max-packages must be from 1 to 100.");
  const root = await realpath(directory);
  const manifestPath = path.join(root, "package.json");
  if (!(await lstat(manifestPath)).isFile()) throw new Error("Project package.json must be a regular file.");
  const handle = await open(manifestPath, "r");
  let manifest: Record<string, unknown>;
  try {
    const buffer = Buffer.alloc(256 * 1024 + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > 256 * 1024) throw new Error("Project package.json exceeds byte limit.");
    const value: unknown = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Project package.json must be an object.");
    manifest = value as Record<string, unknown>;
  } finally { await handle.close(); }
  const declared = new Map<string, { requested: string; sections: string[] }>();
  for (const section of ["dependencies", "optionalDependencies", ...(options.includeDev ? ["devDependencies"] : [])]) {
    const values = manifest[section];
    if (values === undefined) continue;
    if (!values || typeof values !== "object" || Array.isArray(values)) throw new Error(`Project ${section} must be an object.`);
    for (const [name, requested] of Object.entries(values)) {
      if (typeof requested !== "string") throw new Error(`Dependency ${name} must have a string version specification.`);
      const previous = declared.get(name);
      // npm optionalDependencies override dependencies; dev-only requests never override production requests.
      declared.set(name, { requested: section === "devDependencies" && previous ? previous.requested : requested,
        sections: [...(previous?.sections ?? []), section] });
    }
  }
  const dependencies: ProjectDependency[] = [];
  let attempted = 0;
  for (const [name, declaration] of [...declared].sort(([a], [b]) => a.localeCompare(b))) {
    const entry: ProjectDependency = { name, ...declaration, status: "unresolved" };
    dependencies.push(entry);
    if (!/^(?:@[A-Za-z0-9_-][A-Za-z0-9._-]*\/)?[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(name)) {
      entry.status = "omitted"; entry.reason = "Unsupported dependency name."; continue;
    }
    const range = semver.validRange(declaration.requested);
    if (!range) {
      entry.status = "omitted"; entry.reason = "Only semver declarations are inspected; tags, aliases, workspace, file and Git references are not resolved."; continue;
    }
    if (attempted >= maxPackages) {
      entry.status = "omitted"; entry.reason = "Project package limit reached."; continue;
    }
    attempted++;
    const target = path.join(root, "node_modules", ...name.split("/"));
    try {
      let cursor = root;
      for (const part of ["node_modules", ...name.split("/")]) {
        cursor = path.join(cursor, part);
        const info = await lstat(cursor);
        if (info.isSymbolicLink() || !info.isDirectory()) throw Object.assign(new Error("Installed dependency path contains a link or non-directory."), { code: "UNRESOLVED" });
      }
      const manifestInfo = await lstat(path.join(target, "package.json"));
      if (!manifestInfo.isFile()) throw Object.assign(new Error("Installed dependency manifest is not a regular file."), { code: "UNRESOLVED" });
      const pkg = await extractLocalPackage(target, { maxEntries: 10_000, maxTotalBytes: 100 * 1024 * 1024 });
      if (pkg.identity.name !== name || !semver.valid(pkg.identity.version) || !semver.satisfies(pkg.identity.version, range)) {
        entry.reason = "Installed package identity or version does not match the manifest declaration."; continue;
      }
      entry.report = scanExtractedPackage(pkg, options.failOn ? { failOn: options.failOn } : {});
      entry.status = "scanned";
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      const message = error instanceof Error ? error.message : String(error);
      if (["ENOENT", "ENOTDIR", "UNRESOLVED"].includes(code ?? "")) {
        entry.reason = code === "UNRESOLVED" ? message : "Dependency is not installed in this project's node_modules.";
      } else if (/exceeds (file entry|total file byte) limit/.test(message)) {
        entry.status = "omitted"; entry.reason = message;
      } else {
        entry.status = "failed"; entry.reason = "Could not inspect installed package. Check its manifest and read permissions.";
      }
    }
  }
  const count = (status: ProjectDependency["status"]) => dependencies.filter(item => item.status === status).length;
  const complete = dependencies.every(item => item.status === "scanned" && item.report?.coverage?.complete === true);
  const decision: Decision = dependencies.some(item => item.report?.decision === "block") ? "block" :
    !complete || dependencies.some(item => item.report?.decision === "warn") ? "warn" : "allow";
  return { kind: "project", decision, exitCode: count("failed") ? 3 : decision === "block" ? 2 : decision === "warn" ? 1 : 0, dependencies,
    coverage: { scope: "declared-direct-dependencies", source: "installed-node_modules", complete,
      declared: dependencies.length, scanned: count("scanned"), unresolved: count("unresolved"), omitted: count("omitted"), failed: count("failed"),
      maxPackages, includeDev: options.includeDev === true, lockfileVerified: false, transitiveDependenciesAnalyzed: false,
      limitations: ["Installed files are inspected without verifying registry or lockfile integrity.", "Root project source, peer-only declarations, transitive dependencies and linked packages are not scanned.", "No dependency code or installation scripts are executed.", "Each attempted package is limited to 10000 entries and 100 MiB of file sizes; existing text-read limits still apply."] }
  };
}

export function formatProjectText(result: ProjectResult): string {
  const c = result.coverage;
  return ["UNSUS PROJECT REPORT", `Decision: ${result.decision.toUpperCase()} (exit ${result.exitCode})`,
    `Coverage: ${c.scanned}/${c.declared} declared direct dependencies scanned; ${c.unresolved} unresolved; ${c.omitted} omitted; ${c.failed} failed.`,
    "Installed files only. Lockfile integrity and transitive dependencies are not verified.", "",
    ...result.dependencies.map(item => `${item.name}@${item.requested}: ${item.status === "scanned" ? item.report!.decision : item.status}${item.reason ? ` — ${item.reason}` : ""}`), ""].join("\n");
}
