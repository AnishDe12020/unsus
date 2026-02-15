import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { IOC, Finding } from '../types.ts';

const CACHE_DIR = path.join(os.homedir(), '.unsus');
const URLHAUS_CACHE = path.join(CACHE_DIR, 'urlhaus.json');
const CACHE_MAX_AGE = 60 * 60 * 1000; // 1 hour

// URLhaus recent URLs endpoint (JSON, last 1000 malicious URLs)
const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/';

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
    const data = await resp.json() as { urls: any[] };
    return (data.urls || []).map((u: any) => ({
      url: u.url || '',
      host: u.host || '',
      threat: u.threat || '',
      tags: Array.isArray(u.tags) ? u.tags : (u.tags ? [u.tags] : []),
    }));
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
