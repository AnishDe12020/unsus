export type Severity = 'info' | 'warning' | 'danger' | 'critical';

export type FindingType =
  | 'install-script' | 'eval' | 'exec' | 'network' | 'fs-access'
  | 'env-access' | 'obfuscation' | 'crypto-wallet' | 'dynamic-require'
  | 'dynamic-exec' | 'base64-decode' | 'string-construction' | 'vm-exec'
  | 'typosquat' | 'metadata-base64' | 'parse-error';

export type IOCType =
  | 'url' | 'domain' | 'ip' | 'env-var'
  | 'wallet-eth' | 'wallet-btc' | 'wallet-sol' | 'wallet-trx';

export interface Finding {
  type: FindingType;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  code: string;
}

export interface IOC {
  type: IOCType;
  value: string;
  context: string; // file:line
}

export interface DeobfuscationResult {
  original: string;
  deobfuscated: string;
  explanation: string;
  extractedIOCs: IOC[];
  riskLevel: number;
}

export interface ScanResult {
  packageName: string;
  version: string;
  riskScore: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  findings: Finding[];
  iocs: IOC[];
  deobfuscated?: DeobfuscationResult[];
  summary: string;
}

export interface PackageFiles {
  packageJson: Record<string, any>;
  jsFiles: { path: string; content: string }[];
  basePath: string;
}
