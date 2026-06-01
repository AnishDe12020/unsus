import * as acorn from "acorn";

import type { ExtractedPackage, Finding, PackageFile } from "../types.js";
import { createFinding, lineForOffset } from "./finding.js";

const SENSITIVE_ENV_PATTERNS = [
  "TOKEN",
  "SECRET",
  "KEY",
  "PASSWORD",
  "AWS_",
  "GITHUB_TOKEN",
  "NPM_TOKEN",
  "DATABASE_URL",
  "SSH"
];

export function analyzeAst(pkg: ExtractedPackage): Finding[] {
  return pkg.files.flatMap((file) => analyzeSourceFile(file));
}

function analyzeSourceFile(file: PackageFile): Finding[] {
  if (file.kind !== "source" || !file.content) {
    return [];
  }

  const findings: Finding[] = [];
  parseForSyntaxSignal(file);
  addPatternFindings(file, findings, /\beval\s*\(/g, "dynamic_code_execution", "eval_call", "danger", "eval() call", "Source calls eval().");
  addPatternFindings(file, findings, /\bnew\s+Function\s*\(|(?<!new\s)\bFunction\s*\(/g, "dynamic_code_execution", "function_constructor", "danger", "Function constructor", "Source constructs code dynamically.");
  addPatternFindings(file, findings, /require\s*\(\s*["']child_process["']\s*\)|from\s+["']child_process["']/g, "code_execution", "child_process_import", "danger", "child_process import", "Source imports child_process.");
  addPatternFindings(file, findings, /\b(exec|execSync|spawn|spawnSync|execFile)\s*\(/g, "code_execution", "child_process_execution", "danger", "Child process execution", "Source invokes a child process execution API.");
  addPatternFindings(file, findings, /require\s*\(\s*[^"'`\s][^)]+\)/g, "dynamic_code_execution", "dynamic_require", "warning", "Dynamic require", "Source calls require() with a non-literal argument.");
  addPatternFindings(file, findings, /Buffer\.from\s*\([^)]*["']base64["'][^)]*\)|\batob\s*\(/g, "obfuscation", "base64_decode", "warning", "Base64 decode", "Source decodes base64 content.");
  addPatternFindings(file, findings, /String\.fromCharCode\s*\((?:\s*\d+\s*,?){8,}\)/g, "obfuscation", "charcode_chain", "warning", "String.fromCharCode chain", "Source contains a long character-code string construction.");
  addPatternFindings(file, findings, /\b(fetch|http\.request|https\.request|net\.Socket|dns\.resolve)\s*\(/g, "network_access", "network_api", "warning", "Network API", "Source references a network API.");
  addPatternFindings(file, findings, /(?:readFileSync|readFile|writeFileSync|writeFile)\s*\(\s*["'][^"']*(?:\.npmrc|\.ssh|\.aws|\.env)[^"']*["']/g, "filesystem_access", "credential_file_access", "danger", "Credential file path access", "Source references credential-like local file paths.");

  for (const match of file.content.matchAll(/process\.env(?:\.([A-Za-z0-9_]+)|\s*\[\s*["']([^"']+)["']\s*\])?/g)) {
    const envName = match[1] ?? match[2];
    findings.push(
      createFinding({
        category: "credential_access",
        type: "process_env_access",
        severity: envName && isSensitiveEnvName(envName) ? "danger" : "warning",
        title: "Environment variable access",
        message: envName ? `Source reads process.env.${envName}.` : "Source reads process.env.",
        file: file.path,
        line: lineForOffset(file.content, match.index ?? 0),
        code: match[0],
        ...(envName ? { evidence: { envName } } : {}),
        confidence: 0.85
      })
    );
  }

  return findings;
}

function parseForSyntaxSignal(file: PackageFile): void {
  try {
    acorn.parse(file.content ?? "", {
      ecmaVersion: "latest",
      sourceType: "module",
      allowHashBang: true
    });
  } catch {
    try {
      acorn.parse(file.content ?? "", {
        ecmaVersion: "latest",
        sourceType: "script",
        allowHashBang: true
      });
    } catch {
      return;
    }
  }
}

function addPatternFindings(
  file: PackageFile,
  findings: Finding[],
  pattern: RegExp,
  category: Finding["category"],
  type: string,
  severity: Finding["severity"],
  title: string,
  message: string
): void {
  const content = file.content ?? "";
  for (const match of content.matchAll(pattern)) {
    findings.push(
      createFinding({
        category,
        type,
        severity,
        title,
        message,
        file: file.path,
        line: lineForOffset(content, match.index ?? 0),
        code: match[0],
        confidence: 0.82
      })
    );
  }
}

function isSensitiveEnvName(value: string): boolean {
  return SENSITIVE_ENV_PATTERNS.some((pattern) => value.toUpperCase().includes(pattern));
}
