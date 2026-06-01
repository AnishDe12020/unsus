export type {
  BehaviorCategory,
  Decision,
  ExtractedPackage,
  Finding,
  FindingSeverity,
  PackageFile,
  PackageIdentity,
  RiskLevel,
  RiskPolicy,
  SandboxResult,
  SandboxTimelineEvent,
  ScanOptions,
  ScanResult,
  VersionDiffResult
} from "./types.js";

export {
  classifyFile,
  collectPackageFiles,
  extractLocalPackage,
  identityFromPackageJson
} from "./extract/local.js";
export { extractTarballPackage, isSafeTarPath } from "./extract/tarball.js";
export { fetchPackument, resolveNpmPackage, resolveVersion } from "./resolver/npm.js";
export { npmPackumentUrl, parsePackageRequest } from "./resolver/package-manager.js";
