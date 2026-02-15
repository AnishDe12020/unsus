import * as path from 'path';
import * as fs from 'fs';
import type { Finding } from '../types.ts';

/**
 * Run npm audit on a package directory to find known CVEs in its dependencies.
 * Requires a package-lock.json — if missing, generates one with --package-lock-only.
 */
export async function analyzeNpmAudit(pkgDir: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  if (!fs.existsSync(path.join(pkgDir, 'package.json'))) return findings;

  // npm audit needs a lockfile — generate if missing (with timeout to avoid blocking)
  const hasLock = fs.existsSync(path.join(pkgDir, 'package-lock.json'));
  if (!hasLock) {
    try {
      const lock = Bun.spawnSync(['npm', 'install', '--package-lock-only', '--no-audit', '--ignore-scripts'], {
        cwd: pkgDir,
        stdout: 'pipe',
        stderr: 'pipe',
        timeout: 15_000, // 15s max — don't block the scan
      });
      if (lock.exitCode !== 0) return findings;
    } catch {
      return findings;
    }
  }

  try {
    const proc = Bun.spawnSync(['npm', 'audit', '--json'], {
      cwd: pkgDir,
      stdout: 'pipe',
      stderr: 'pipe',
      timeout: 10_000, // 10s max
    });

    // npm audit exits 1 when vulns found — output is still valid JSON
    const stdout = proc.stdout.toString();
    if (!stdout.trim()) return findings;

    const data = JSON.parse(stdout);
    if (!data?.vulnerabilities) return findings;

    // summary finding
    const meta = data.metadata?.vulnerabilities || {};
    const total = meta.total || 0;
    const critical = meta.critical || 0;
    const high = meta.high || 0;
    const moderate = meta.moderate || 0;
    const low = meta.low || 0;

    if (total > 0) {
      let severity: Finding['severity'] = 'info';
      if (critical > 0) severity = 'critical';
      else if (high > 0) severity = 'danger';
      else if (moderate > 0) severity = 'warning';

      findings.push({
        type: 'npm-audit',
        severity,
        message: `npm audit: ${total} known vulnerabilities (${critical} critical, ${high} high, ${moderate} moderate, ${low} low)`,
        file: 'package.json',
        line: 0,
        code: `${total} vulnerabilities`,
      });
    }

    // individual CVEs
    for (const [pkgName, info] of Object.entries(data.vulnerabilities) as [string, any][]) {
      if (!info.via) continue;
      const vias = Array.isArray(info.via) ? info.via : [info.via];

      for (const via of vias) {
        if (typeof via === 'object' && via.title) {
          findings.push({
            type: 'npm-audit',
            severity: mapSeverity(info.severity),
            message: `${pkgName}: ${via.title}`,
            file: 'package.json',
            line: 0,
            code: via.url || `CVE in ${pkgName}`,
          });
        }
      }
    }
  } catch {
    // npm audit not available or failed — skip silently
  }

  return findings;
}

function mapSeverity(s: string): Finding['severity'] {
  switch (s?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'danger';
    case 'moderate': return 'warning';
    default: return 'info';
  }
}
