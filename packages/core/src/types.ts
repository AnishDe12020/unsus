export type RiskLevel = "safe" | "low" | "medium" | "high" | "critical";

export type Decision = "allow" | "warn" | "block";

export type FindingSeverity = "info" | "warning" | "danger" | "critical";

export type BehaviorCategory =
  | "install_time_execution"
  | "code_execution"
  | "dynamic_code_execution"
  | "credential_access"
  | "network_access"
  | "filesystem_access"
  | "obfuscation"
  | "binary_payload"
  | "typosquat"
  | "metadata_anomaly"
  | "version_diff_anomaly"
  | "provenance_anomaly"
  | "known_vulnerability"
  | "threat_intel"
  | "sandbox_behavior";

export interface Finding {
  id: string;
  category: BehaviorCategory;
  type: string;
  severity: FindingSeverity;
  title: string;
  message: string;
  file?: string;
  line?: number;
  code?: string;
  evidence?: Record<string, unknown>;
  confidence: number;
}

export interface PackageIdentity {
  name: string;
  version: string;
  requested?: string;
  registry?: string;
  tarballUrl?: string;
  integrity?: string;
  repositoryUrl?: string;
}

export interface ExtractedPackage {
  identity: PackageIdentity;
  rootPath: string;
  files: PackageFile[];
  packageJson: Record<string, unknown>;
  isLocal: boolean;
  cleanup?: () => Promise<void> | void;
  /** Verified registry archive, available until cleanup. */
  tarballPath?: string;
}

export interface PackageFile {
  path: string;
  size: number;
  kind: "source" | "json" | "binary" | "text" | "other";
  content?: string;
  headerBytes?: Uint8Array;
  /** Full-byte digest for files whose content was not retained. */
  contentHash?: string;
}

export interface ScanResult {
  package: PackageIdentity;
  riskScore: number;
  riskLevel: RiskLevel;
  decision: Decision;
  findings: Finding[];
  summary: string;
  generatedAt: string;
  sandbox?: SandboxResult;
  diff?: VersionDiffResult;
  coverage?: {
    scope: "direct-package";
    complete: boolean;
    files: number;
    textFilesAnalyzed: number;
    omittedTextFiles: string[];
    dependenciesAnalyzed: false;
    limitations: string[];
  };
}

export interface VersionDiffResult {
  from: PackageIdentity;
  to: PackageIdentity;
  findings: Finding[];
  changedFiles: string[];
  addedFiles: string[];
  removedFiles: string[];
  packageJsonChanges: Record<string, unknown>;
}

export interface SandboxTimelineEvent {
  timeMs: number;
  type: string;
  message: string;
  evidence?: Record<string, unknown>;
}

export interface SandboxResult {
  enabled: boolean;
  timedOut: boolean;
  exitCode?: number;
  timeline: SandboxTimelineEvent[];
  findings: Finding[];
}

export type DynamicSandboxRunner = (pkg: ExtractedPackage) => Promise<SandboxResult>;

export interface ScanOptions {
  registry?: string;
  dynamic?: boolean;
  failOn?: RiskLevel;
  dynamicRunner?: DynamicSandboxRunner;
  allowRemoteDynamic?: boolean;
}

export interface RiskPolicy {
  failOn?: RiskLevel;
  allowLevels: RiskLevel[];
  warnLevels: RiskLevel[];
  blockLevels: RiskLevel[];
}
