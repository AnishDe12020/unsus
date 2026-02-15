// src/analyzers/npm-audit.ts
import { execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { Finding, PackageJson, FileEntry } from '../types';

export interface AuditResult {
  hasVulnerabilities: boolean;
  total: number;
  critical: number;
  high: number;
  moderate: number;
  low: number;
  info: number;
}

/**
 * Run npm audit on a package
 */
export async function analyzeWithNpmAudit(
  files: FileEntry[],
  packageJson: PackageJson,
  packagePath?: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  try {
    // If we have a local path, run npm audit there
    if (packagePath && fs.existsSync(packagePath)) {
      const auditResult = await runNpmAuditOnPath(packagePath);
      findings.push(...convertAuditToFindings(auditResult, packageJson));
    } else {
      // For downloaded packages, check their dependencies
      const auditResult = await analyzePackageJsonDependencies(packageJson);
      findings.push(...auditResult);
    }
    
  } catch (error: any) {
    console.warn('⚠️  npm audit check skipped:', error.message);
  }
  
  return findings;
}

/**
 * Run npm audit on a local directory
 */
async function runNpmAuditOnPath(packagePath: string): Promise<any> {
  try {
    // Run npm audit --json
    const output = execSync('npm audit --json', {
      cwd: packagePath,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'] // Suppress stderr
    });
    
    return JSON.parse(output);
    
  } catch (error: any) {
    // npm audit returns exit code 1 if vulnerabilities found
    // The output is still valid JSON
    if (error.stdout) {
      try {
        return JSON.parse(error.stdout);
      } catch {
        return null;
      }
    }
    return null;
  }
}

/**
 * Analyze package.json dependencies against known vulnerabilities
 */
async function analyzePackageJsonDependencies(
  packageJson: PackageJson
): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  // Check if package has dependencies
  const allDeps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies
  };
  
  if (Object.keys(allDeps).length === 0) {
    return findings;
  }
  
  // Create a temporary directory to check dependencies
  const tempDir = path.join(process.cwd(), '.npm-audit-temp');
  
  try {
    // Create temp directory
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    // Write a minimal package.json with these dependencies
    const tempPackageJson = {
      name: 'temp-audit-check',
      version: '1.0.0',
      dependencies: packageJson.dependencies || {},
      devDependencies: packageJson.devDependencies || {}
    };
    
    fs.writeFileSync(
      path.join(tempDir, 'package.json'),
      JSON.stringify(tempPackageJson, null, 2)
    );
    
    // Run npm install (this creates package-lock.json needed for audit)
    execSync('npm install --package-lock-only --no-audit', {
      cwd: tempDir,
      stdio: 'ignore'
    });
    
    // Run npm audit
    const auditResult = await runNpmAuditOnPath(tempDir);
    
    if (auditResult) {
      findings.push(...convertAuditToFindings(auditResult, packageJson));
    }
    
  } catch (error: any) {
    console.warn('Could not run dependency audit:', error.message);
  } finally {
    // Cleanup
    try {
      if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    } catch {}
  }
  
  return findings;
}

/**
 * Convert npm audit results to Finding objects
 */
function convertAuditToFindings(
  auditData: any,
  packageJson: PackageJson
): Finding[] {
  const findings: Finding[] = [];
  
  if (!auditData || !auditData.vulnerabilities) {
    return findings;
  }
  
  // Get vulnerability summary
  const metadata = auditData.metadata || {};
  const vulns = metadata.vulnerabilities || {};
  
  // Add summary finding
  const total = vulns.total || 0;
  const critical = vulns.critical || 0;
  const high = vulns.high || 0;
  const moderate = vulns.moderate || 0;
  const low = vulns.low || 0;
  
  if (total > 0) {
    let severity: 'info' | 'warning' | 'danger' | 'critical' = 'info';
    if (critical > 0) severity = 'critical';
    else if (high > 0) severity = 'danger';
    else if (moderate > 0) severity = 'warning';
    
    findings.push({
      type: 'npm-audit' as any,
      severity,
      message: `npm audit found ${total} known vulnerabilities (${critical} critical, ${high} high, ${moderate} moderate, ${low} low)`,
      file: 'package.json',
      line: 0,
      code: `Total vulnerabilities: ${total}`
    });
  }
  
  // Add individual vulnerability findings
  const vulnDetails = auditData.vulnerabilities || {};
  
  for (const [pkgName, vulnInfo] of Object.entries(vulnDetails)) {
    const info: any = vulnInfo;
    
    if (info.severity && info.via) {
      const vias = Array.isArray(info.via) ? info.via : [info.via];
      
      for (const via of vias) {
        if (typeof via === 'object' && via.title) {
          findings.push({
            type: 'npm-audit' as any,
            severity: mapAuditSeverity(info.severity),
            message: `${pkgName}: ${via.title}`,
            file: 'package.json',
            line: 0,
            code: via.url || `CVE in ${pkgName}`
          });
        }
      }
    }
  }
  
  return findings;
}

/**
 * Map npm audit severity to our severity levels
 */
function mapAuditSeverity(
  auditSeverity: string
): 'info' | 'warning' | 'danger' | 'critical' {
  switch (auditSeverity.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'danger';
    case 'moderate': return 'warning';
    case 'low': return 'info';
    default: return 'info';
  }
}

// Export for use in scanner
export { analyzeWithNpmAudit as analyzeNpmAudit };
