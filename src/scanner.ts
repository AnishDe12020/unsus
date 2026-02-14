import * as fs from 'fs';
import * as path from 'path';
import type { ScanResult, Finding, IOC, PackageFiles } from './types.ts';
import { analyzeMetadata } from './analyzers/metadata.ts';
import { analyzeAST } from './analyzers/ast.ts';
import { analyzeEntropy } from './analyzers/entropy.ts';
import { extractIOCs } from './analyzers/regex.ts';

const JS_EXT = new Set(['.js', '.mjs', '.cjs']);

export async function scan(target: string): Promise<ScanResult> {
  const dir = path.resolve(target);
  const pkg = loadPkg(dir);

  // allSettled so one crash doesn't kill the rest
  const results = await Promise.allSettled([
    Promise.resolve(analyzeMetadata(pkg)),
    Promise.resolve(analyzeAST(pkg.jsFiles)),
    Promise.resolve(analyzeEntropy(pkg.jsFiles)),
    Promise.resolve(extractIOCs(pkg.jsFiles)),
  ]);

  const findings: Finding[] = [];
  const iocs: IOC[] = [];

  if (results[0]?.status === 'fulfilled') {
    findings.push(...results[0].value.findings);
    iocs.push(...results[0].value.iocs);
  }
  if (results[1]?.status === 'fulfilled') findings.push(...results[1].value);
  if (results[2]?.status === 'fulfilled') findings.push(...results[2].value);
  if (results[3]?.status === 'fulfilled') iocs.push(...results[3].value);

  // log crashes
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

  const score = calcScore(findings);
  const level = toLevel(score);

  return {
    packageName: pkg.packageJson.name || path.basename(dir),
    version: pkg.packageJson.version || '0.0.0',
    riskScore: score,
    riskLevel: level,
    findings,
    iocs: uniqIOCs,
    summary: makeSummary(findings, uniqIOCs, score, level),
  };
}

function loadPkg(dir: string): PackageFiles {
  let packageJson: Record<string, any> = {};
  try { packageJson = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf-8')); } catch {}

  const jsFiles: { path: string; content: string }[] = [];
  walk(dir, jsFiles, dir);
  return { packageJson, jsFiles, basePath: dir };
}

function walk(dir: string, out: { path: string; content: string }[], base: string) {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { walk(full, out, base); continue; }
    if (e.isFile() && JS_EXT.has(path.extname(e.name))) {
      try { out.push({ path: path.relative(base, full), content: fs.readFileSync(full, 'utf-8') }); } catch {}
    }
  }
}

function calcScore(findings: Finding[]): number {
  let s = 0;
  for (const f of findings) {
    if (f.severity === 'critical') s += 3;
    else if (f.severity === 'danger') s += 2;
    else if (f.severity === 'warning') s += 1;
    else s += 0.25;
  }

  const types = new Set(findings.map(f => f.type));
  const has = (t: string) => types.has(t as any);

  // compound risk
  if (has('install-script') && (has('network') || has('exec'))) s *= 1.5;
  if ((has('obfuscation') || has('base64-decode')) && has('exec')) s *= 2.0;
  if (has('env-access') && has('network')) s *= 1.5;

  return Math.min(s, 10);
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
