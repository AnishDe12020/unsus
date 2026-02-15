/*import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { IOC, Finding } from '../types.ts';

const CACHE_DIR = path.join(os.homedir(), '.unsus');
const URLHAUS_CACHE = path.join(CACHE_DIR, 'urlhaus.json');
const CACHE_MAX_AGE = 60 * 60 * 1000; // 1 hour

// URLhaus bulk download (no auth needed, returns recent malicious URLs as JSON)
const URLHAUS_API = 'https://urlhaus.abuse.ch/downloads/json_recent/';

interface URLhausEntry {
  url: string;
  host: string;
  threat: string;
  tags: string[];
}

interface ThreatDB {
  domains: Set<string>;
  urls: Set<string>;
  fetchedAt: number;
}

let cachedDB: ThreatDB | null = null;

async function fetchURLhaus(): Promise<URLhausEntry[]> {
  try {
    const resp = await fetch(URLHAUS_API);
    if (!resp.ok) throw new Error(`URLhaus API ${resp.status}`);
    const data = await resp.json() as Record<string, any[]>;
    // bulk format: { "id": [ { url, url_status, threat, tags, ... } ] }
    const entries: URLhausEntry[] = [];
    for (const [, items] of Object.entries(data)) {
      if (!Array.isArray(items)) continue;
      for (const u of items) {
        let host = '';
        try { host = new URL(u.url).hostname; } catch {}
        entries.push({
          url: u.url || '',
          host,
          threat: u.threat || '',
          tags: Array.isArray(u.tags) ? u.tags : (u.tags ? [u.tags] : []),
        });
      }
    }
    return entries;
  } catch (e: any) {
    console.error(`[!] URLhaus fetch failed: ${e.message}`);
    return [];
  }
}

function loadCache(): ThreatDB | null {
  try {
    const raw = fs.readFileSync(URLHAUS_CACHE, 'utf-8');
    const data = JSON.parse(raw);
    if (Date.now() - data.fetchedAt > CACHE_MAX_AGE) return null;
    return {
      domains: new Set(data.domains),
      urls: new Set(data.urls),
      fetchedAt: data.fetchedAt,
    };
  } catch {
    return null;
  }
}

function saveCache(db: ThreatDB) {
  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(URLHAUS_CACHE, JSON.stringify({
      domains: [...db.domains],
      urls: [...db.urls],
      fetchedAt: db.fetchedAt,
    }));
  } catch {}
}

async function getThreatDB(): Promise<ThreatDB> {
  if (cachedDB && Date.now() - cachedDB.fetchedAt < CACHE_MAX_AGE) return cachedDB;

  const fromDisk = loadCache();
  if (fromDisk) { cachedDB = fromDisk; return fromDisk; }

  const entries = await fetchURLhaus();
  const db: ThreatDB = {
    domains: new Set<string>(),
    urls: new Set<string>(),
    fetchedAt: Date.now(),
  };

  for (const e of entries) {
    if (e.host) db.domains.add(e.host.toLowerCase());
    if (e.url) db.urls.add(e.url.toLowerCase());
  }

  saveCache(db);
  cachedDB = db;
  return db;
}

// VirusTotal: optional, needs VIRUSTOTAL_API_KEY
const VT_API = 'https://www.virustotal.com/api/v3';
const VT_RATE_DELAY = 15500; // ~4 req/min

async function checkVirusTotal(ioc: string, type: 'domains' | 'ip_addresses' | 'urls'): Promise<{ malicious: number; source: string } | null> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return null;

  try {
    let url: string;
    if (type === 'urls') {
      // VT requires base64-encoded URL identifier
      const id = Buffer.from(ioc).toString('base64').replace(/=+$/, '');
      url = `${VT_API}/urls/${id}`;
    } else {
      url = `${VT_API}/${type}/${ioc}`;
    }

    const resp = await fetch(url, { headers: { 'x-apikey': apiKey } });
    if (!resp.ok) return null;

    const data = await resp.json() as any;
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) return null;

    const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
    if (malicious > 0) {
      return { malicious, source: `VirusTotal (${malicious} engines)` };
    }
  } catch {}
  return null;
}

export async function checkThreatIntel(iocs: IOC[]): Promise<{ findings: Finding[]; enriched: IOC[] }> {
  const findings: Finding[] = [];
  const db = await getThreatDB();

  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  let vtChecks = 0;
  const MAX_VT_CHECKS = 4; // stay under free tier limit

  for (const ioc of iocs) {
    let matched = false;

    // URLhaus: check domains and URLs
    if (ioc.type === 'domain' && db.domains.has(ioc.value.toLowerCase())) {
      ioc.threatMatch = { source: 'URLhaus', detail: 'Known malicious domain' };
      findings.push({
        type: 'threat-intel',
        severity: 'critical',
        message: `Malicious domain (URLhaus): ${ioc.value}`,
        file: ioc.context.split(':')[0] || 'unknown',
        line: parseInt(ioc.context.split(':')[1] || '0', 10),
        code: ioc.value,
      });
      matched = true;
    }

    if (ioc.type === 'url') {
      const lower = ioc.value.toLowerCase();
      if (db.urls.has(lower) || db.domains.has(extractHost(lower))) {
        ioc.threatMatch = { source: 'URLhaus', detail: 'Known malicious URL' };
        findings.push({
          type: 'threat-intel',
          severity: 'critical',
          message: `Malicious URL (URLhaus): ${ioc.value}`,
          file: ioc.context.split(':')[0] || 'unknown',
          line: parseInt(ioc.context.split(':')[1] || '0', 10),
          code: ioc.value,
        });
        matched = true;
      }
    }

    if (ioc.type === 'ip' && db.domains.has(ioc.value)) {
      ioc.threatMatch = { source: 'URLhaus', detail: 'Known malicious IP' };
      findings.push({
        type: 'threat-intel',
        severity: 'critical',
        message: `Malicious IP (URLhaus): ${ioc.value}`,
        file: ioc.context.split(':')[0] || 'unknown',
        line: parseInt(ioc.context.split(':')[1] || '0', 10),
        code: ioc.value,
      });
      matched = true;
    }

    // VirusTotal: check unmatched domains/IPs/URLs (limited requests)
    if (!matched && vtKey && vtChecks < MAX_VT_CHECKS) {
      let vtType: 'domains' | 'ip_addresses' | 'urls' | null = null;
      if (ioc.type === 'domain') vtType = 'domains';
      else if (ioc.type === 'ip') vtType = 'ip_addresses';
      else if (ioc.type === 'url') vtType = 'urls';

      if (vtType) {
        vtChecks++;
        const vt = await checkVirusTotal(ioc.value, vtType);
        if (vt) {
          ioc.threatMatch = { source: 'VirusTotal', detail: vt.source };
          findings.push({
            type: 'threat-intel',
            severity: vt.malicious >= 5 ? 'critical' : 'danger',
            message: `Flagged by ${vt.source}: ${ioc.value}`,
            file: ioc.context.split(':')[0] || 'unknown',
            line: parseInt(ioc.context.split(':')[1] || '0', 10),
            code: ioc.value,
          });
        }
        // throttle VT requests
        if (vtChecks < MAX_VT_CHECKS) await new Promise(r => setTimeout(r, VT_RATE_DELAY));
      }
    }
  }

  return { findings, enriched: iocs };
}

function extractHost(url: string): string {
  try { return new URL(url).hostname; } catch { return ''; }
}
*/


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
// ========== ADD THIS IMPORT ==========
import { analyzeNpmAudit } from './analyzers/npm-audit.ts';
// =====================================

const JS_EXT = new Set(['.js', '.mjs', '.cjs']);
const BIN_EXT = new Set(['.exe', '.dll', '.so', '.dylib', '.bin', '.sh', '.bat', '.ps1', '.cmd']);

export async function scan(target: string, opts?: { dynamic?: boolean }): Promise<ScanResult> {
  const dir = path.resolve(target);
  const pkg = loadPkg(dir);

  // ========== MODIFY THIS SECTION ==========
  // Add npm audit as first analyzer (Layer 1: Known CVEs)
  const results = await Promise.allSettled([
    // LAYER 1: npm audit check
    Promise.resolve(analyzeNpmAudit(
      pkg.jsFiles.map(f => ({ path: f.path, content: f.content, size: f.content.length })),
      pkg.packageJson,
      pkg.basePath
    )).catch(() => [] as Finding[]),
    
    // LAYER 2: Behavioral analyzers
    Promise.resolve(analyzeMetadata(pkg)),
    Promise.resolve(analyzeAST(pkg.jsFiles)),
    Promise.resolve(analyzeEntropy(pkg.jsFiles)),
    Promise.resolve(extractIOCs(pkg.jsFiles)),
    Promise.resolve(analyzeBinaries(pkg)),
  ]);

  const findings: Finding[] = [];
  const iocs: IOC[] = [];

  // Collect npm audit results (index 0)
  if (results[0]?.status === 'fulfilled') {
    findings.push(...results[0].value);
  }

  // Collect metadata results (now index 1)
  if (results[1]?.status === 'fulfilled') {
    findings.push(...results[1].value.findings);
    iocs.push(...results[1].value.iocs);
  }
  
  // Collect AST results (now index 2)
  if (results[2]?.status === 'fulfilled') findings.push(...results[2].value);
  
  // Collect entropy results (now index 3)
  if (results[3]?.status === 'fulfilled') findings.push(...results[3].value);
  
  // Collect IOCs (now index 4)
  if (results[4]?.status === 'fulfilled') iocs.push(...results[4].value);
  
  // Collect binary results (now index 5)
  if (results[5]?.status === 'fulfilled') findings.push(...results[5].value);
  // ========== END MODIFICATION ==========

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

  // dedup findings from same type+file+line (e.g. multiple fetch() on same line)
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
  
  // ========== ADD THIS ==========
  // Boost score if npm audit found critical CVEs
  if (has('npm-audit')) s *= 1.2;
  // ==============================

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
