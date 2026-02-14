import type { IOC } from '../types.ts';

const PATTERNS: { type: IOC['type']; re: RegExp }[] = [
  { type: 'wallet-eth', re: /0x[a-fA-F0-9]{40}/g },
  { type: 'wallet-btc', re: /(?:^|[^a-zA-Z0-9])([13][a-km-zA-HJ-NP-Z1-9]{25,34})/g },
  { type: 'wallet-btc', re: /bc1[a-zA-HJ-NP-Z0-9]{25,90}/g },
  { type: 'wallet-sol', re: /(?:^|[^a-zA-Z0-9/])([1-9A-HJ-NP-Za-km-z]{32,44})/g },
  { type: 'wallet-trx', re: /T[a-zA-HJ-NP-Z0-9]{33}/g },
  { type: 'url', re: /https?:\/\/[^\s'"`,)\]}>${}]+/g },
  { type: 'ip', re: /(?:^|[^0-9])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/g },
  { type: 'env-var', re: /process\.env\.([A-Z_][A-Z0-9_]*)/g },
  { type: 'env-var', re: /process\.env\[['"]([A-Z_][A-Z0-9_]*)['"]\]/g },
  { type: 'domain', re: /hostname:\s*['"]([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)['"]/g },
  { type: 'domain', re: /['"]([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)['"]/g },
];

const SAFE_DOMAINS = new Set([
  'registry.npmjs.org', 'npmjs.com', 'github.com', 'nodejs.org', 'localhost',
]);

export function extractIOCs(files: { path: string; content: string }[]): IOC[] {
  const iocs: IOC[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    for (const { type, re } of PATTERNS) {
      const regex = new RegExp(re.source, re.flags);
      let m;
      while ((m = regex.exec(file.content)) !== null) {
        const raw = (m[1] || m[0]).trim().replace(/['"`;,)\]}]+$/, '');
        if (!raw || raw.length < 4) continue;

        const key = `${type}:${raw}`;
        if (seen.has(key)) continue;
        seen.add(key);

        // fp filters
        if (type === 'wallet-sol' && /^[a-z]+$/.test(raw)) continue;
        if (type === 'wallet-trx') {
          if (raw.length !== 34 || /[0OIl+/=]/.test(raw)) continue;
        }
        if (type === 'url') {
          try { if (SAFE_DOMAINS.has(new URL(raw).hostname)) continue; } catch {}
        }
        if (type === 'domain') {
          if (SAFE_DOMAINS.has(raw)) continue;
          if (/\.(json|js|ts|mjs|cjs|md|txt|log|css|html)$/i.test(raw)) continue;
        }
        if (type === 'ip') {
          if (raw.startsWith('0.') || raw.startsWith('127.') || /^\d+\.\d+\.\d+$/.test(raw)) continue;
        }
        if (type === 'env-var' && raw === 'UNSUS_TEST_NETWORK') continue;

        // find line number
        let ln = 1;
        for (let i = 0; i < m.index; i++) if (file.content[i] === '\n') ln++;

        iocs.push({ type, value: raw, context: `${file.path}:${ln}` });
      }
    }
  }
  return iocs;
}
