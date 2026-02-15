import * as fs from 'fs';
import * as path from 'path';
import type { ScanResult, Finding, IOC, PackageFiles } from './types.ts';
import { analyzeMetadata } from './analyzers/metadata.ts';
import { analyzeAST } from './analyzers/ast.ts';
import { analyzeEntropy } from './analyzers/entropy.ts';
import { extractIOCs } from './analyzers/regex.ts';
import { analyzeBinaries } from './analyzers/binary.ts';
import { runDynamic } from './dynamic/sandbox.ts';
import { checkThreatIntel } from './analyzers/threatintel.ts';
import { analyzeNpmAudit } from './analyzers/npm-audit.ts';

const JS_EXT = new Set(['.js', '.mjs', '.cjs']);
const BIN_EXT = new Set(['.exe', '.dll', '.so', '.dylib', '.bin', '.sh', '.bat', '.ps1', '.cmd']);

export async function scan(target: string, opts?: { dynamic?: boolean }): Promise<ScanResult> {
  const dir = path.resolve(target);
  const pkg = loadPkg(dir);

  const results = await Promise.allSettled([
    analyzeNpmAudit(dir),
    Promise.resolve(analyzeMetadata(pkg)),
    Promise.resolve(analyzeAST(pkg.jsFiles)),
    Promise.resolve(analyzeEntropy(pkg.jsFiles)),
    Promise.resolve(extractIOCs(pkg.jsFiles)),
    Promise.resolve(analyzeBinaries(pkg)),
  ]);

  const findings: Finding[] = [];
  const iocs: IOC[] = [];

  // [0] npm audit
  if (results[0]?.status === 'fulfilled') findings.push(...results[0].value);
  // [1] metadata
  if (results[1]?.status === 'fulfilled') {
    findings.push(...results[1].value.findings);
    iocs.push(...results[1].value.iocs);
  }
  // [2] AST
  if (results[2]?.status === 'fulfilled') findings.push(...results[2].value);
  // [3] entropy
  if (results[3]?.status === 'fulfilled') findings.push(...results[3].value);
  // [4] IOCs
  if (results[4]?.status === 'fulfilled') iocs.push(...results[4].value);
  // [5] binaries
  if (results[5]?.status === 'fulfilled') findings.push(...results[5].value);

  for (const r of results)
    if (r.status === 'rejected') console.error('[!] analyzer error:', r.reason?.message || r.reason);

  // dedup iocs
  const seenIOC = new Set<string>();
  const uniqIOCs = iocs.filter(i => {
    const k = `${i.type}:${i.value}`;
    if (seenIOC.has(k)) return false;
    seenIOC.add(k);
    return true;
  });

  // threat intel enrichment
  try {
    const ti = await checkThreatIntel(uniqIOCs);
    findings.push(...ti.findings);
  } catch (e: any) {
    console.error('[!] threat intel check failed:', e.message);
  }

  // dynamic analysis
  let dynamicAnalysis;
  if (opts?.dynamic) {
    try {
      const dyn = await runDynamic(dir);
      findings.push(...dyn.findings);
      dynamicAnalysis = dyn.result;
    } catch (e: any) {
      console.error('[!] dynamic analysis failed:', e.message);
    }
  }

  // dedup findings from same type+file+line
  const dedupKey = (f: Finding) => `${f.type}:${f.file}:${f.line}`;
  const seenFindings = new Set<string>();
  const dedupedFindings = findings.filter(f => {
    const k = dedupKey(f);
    if (seenFindings.has(k)) return false;
    seenFindings.add(k);
    return true;
  });
  findings.length = 0;
  findings.push(...dedupedFindings);

  const score = calcScore(findings);
  const level = toLevel(score);

  return {
    packageName: pkg.packageJson.name || path.basename(dir),
    version: pkg.packageJson.version || '0.0.0',
    riskScore: score,
    riskLevel: level,
    findings,
    iocs: uniqIOCs,
    dynamicAnalysis,
    summary: makeSummary(findings, uniqIOCs, score, level),
  };
}

function loadPkg(dir: string): PackageFiles {
  let packageJson: Record<string, any> = {};
  try { packageJson = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf-8')); } catch {}

  const jsFiles: { path: string; content: string }[] = [];
  const binaryFiles: { path: string; header: Buffer }[] = [];
  walk(dir, jsFiles, binaryFiles, dir);
  return { packageJson, jsFiles, binaryFiles, basePath: dir };
}

function walk(
  dir: string,
  jsOut: { path: string; content: string }[],
  binOut: { path: string; header: Buffer }[],
  base: string,
) {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { walk(full, jsOut, binOut, base); continue; }
    if (!e.isFile()) continue;

    const ext = path.extname(e.name);
    const rel = path.relative(base, full);

    if (JS_EXT.has(ext)) {
      try { jsOut.push({ path: rel, content: fs.readFileSync(full, 'utf-8') }); } catch {}
    }
    if (BIN_EXT.has(ext) || (!JS_EXT.has(ext) && ext !== '.json' && ext !== '.md' && ext !== '.txt')) {
      try {
        const fd = fs.openSync(full, 'r');
        const buf = Buffer.alloc(16);
        fs.readSync(fd, buf, 0, 16, 0);
        fs.closeSync(fd);
        binOut.push({ path: rel, header: buf });
      } catch {}
    }
  }
}

const WEIGHTS: Record<string, number[]> = {
  critical: [2.5, 1.5, 1.0],  // 4th+ = 0.5
  danger:   [1.5, 1.0],       // 3rd+ = 0.5
  warning:  [0.5, 0.3],       // 3rd+ = 0.15
};

function calcScore(findings: Finding[]): number {
  const counts: Record<string, number> = { critical: 0, danger: 0, warning: 0, info: 0 };
  let s = 0;

  for (const f of findings) {
    const sev = f.severity;
    const n = counts[sev] ?? 0;
    counts[sev] = n + 1;

    if (sev === 'info') { s += 0.1; continue; }

    const w = WEIGHTS[sev];
    if (!w) continue;
    s += n < w.length ? w[n]! : (sev === 'warning' ? 0.15 : 0.5);
  }

  const types = new Set(findings.map(f => f.type));
  const has = (t: string) => types.has(t as any);

  // compound risk
  if (has('install-script') && (has('network') || has('exec'))) s *= 1.3;
  if ((has('obfuscation') || has('base64-decode')) && has('exec')) s *= 1.5;
  if (has('env-access-sensitive') && has('network')) s *= 1.3;
  if (has('cryptominer') && has('network')) s *= 1.5;
  if (has('geo-trigger') && has('fs-access')) s *= 1.3;
  if (has('dynamic-network') && has('install-script')) s *= 1.5;
  if (has('threat-intel')) s *= 1.5;
  if (has('npm-audit')) s *= 1.2;

  return Math.min(Math.round(s * 10) / 10, 10);
}

function toLevel(s: number): ScanResult['riskLevel'] {
  if (s <= 1) return 'safe';
  if (s <= 3) return 'low';
  if (s <= 5) return 'medium';
  if (s <= 7.5) return 'high';
  return 'critical';
}

function makeSummary(findings: Finding[], iocs: IOC[], score: number, level: string) {
  const crit = findings.filter(f => f.severity === 'critical').length;
  const danger = findings.filter(f => f.severity === 'danger').length;
  const parts: string[] = [];
  if (crit) parts.push(`${crit} critical`);
  if (danger) parts.push(`${danger} dangerous`);
  if (iocs.length) parts.push(`${iocs.length} IOCs extracted`);
  if (!parts.length) return 'No suspicious patterns detected.';
  return `Risk ${level.toUpperCase()} (${score.toFixed(1)}/10): ${parts.join(', ')} findings.`;
}
