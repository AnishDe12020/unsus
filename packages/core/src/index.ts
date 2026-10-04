export type {
  BehaviorCategory,
  Decision,
  DynamicSandboxRunner,
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
export { npmPackumentUrl, parsePackageRequest, isNpmPackageRequest } from "./resolver/package-manager.js";
export { analyzeMetadata } from "./analyzers/metadata.js";
export { analyzeAst } from "./analyzers/ast.js";
export { analyzeEntropy } from "./analyzers/entropy.js";
export { analyzeIocs } from "./analyzers/ioc.js";
export { analyzeBinary } from "./analyzers/binary.js";
export {
  calculateRiskScore,
  decisionForFindings,
  decisionFromPolicy,
  defaultPolicy,
  riskLevelFromScore
} from "./scoring/score.js";
export { analyzePackage, scanExtractedPackage, scanPackage, scanTarget } from "./scan.js";
export { compareExtractedPackages, diffTargets } from "./diff/version-diff.js";
export { formatJsonReport } from "./report/json.js";
export { formatSarifReport } from "./report/sarif.js";
export { formatDiffText, formatScanText } from "./report/text.js";
