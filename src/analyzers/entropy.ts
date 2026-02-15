import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import type { Finding } from '../types.ts';
import { shannonEntropy, truncate } from '../utils.ts';

const THRESHOLD = 5.0;       // raised: normal code ~3-4, regexes ~4.5, obfuscated ~5-6+
const DANGER_THRESHOLD = 5.8; // high confidence obfuscation
const MIN_LEN = 24;          // short strings are rarely meaningful obfuscation

// patterns that naturally have high entropy but aren't obfuscation
const BENIGN_PATTERNS = [
  /^[\\dDwWsSbBnrtfv.*+?^${}()|[\]\/\-\[\]!:=<>,;&#@~`_%]+$/, // regex-heavy strings
  /https?:\/\//,             // URLs
  /^\w+:\/\//,               // protocol URLs
  /[A-Z][a-z]+[A-Z]/,        // camelCase (normal code identifiers)
  /\\[dDwWsSbB]/,            // regex character classes
  /\(\?[:!=<]/,              // regex lookahead/lookbehind
  /^\s*function\s/,          // code-as-string (templates)
  /^\s*import\s/,            // import statements as strings
  /^\s*export\s/,            // export statements as strings
  /Unsupported|deprecated|WARNING|ERROR/i, // error/warning messages
  /\.(com|org|net|io|js|ts|json|md)\b/,   // strings with domains/file extensions
];

function isBenign(s: string): boolean {
  return BENIGN_PATTERNS.some(re => re.test(s));
}

export function analyzeEntropy(files: { path: string; content: string }[]): Finding[] {
  const findings: Finding[] = [];

  for (const f of files) {
    // skip minified duplicates — they produce the same findings as the source
    if (f.path.endsWith('.min.js') || f.path.endsWith('.min.mjs') || f.path.endsWith('.min.cjs')) continue;

    let ast;
    try {
      ast = acorn.parse(f.content, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
    } catch {
      try { ast = acorn.parse(f.content, { ecmaVersion: 'latest', sourceType: 'script', locations: true }); }
      catch { continue; }
    }

    walk.simple(ast, {
      Literal(node: any) {
        if (typeof node.value !== 'string' || node.value.length < MIN_LEN) return;
        if (isBenign(node.value)) return;
        const ent = shannonEntropy(node.value);
        if (ent < THRESHOLD) return;

        findings.push({
          type: 'obfuscation',
          severity: ent >= DANGER_THRESHOLD ? 'danger' : 'warning',
          message: `High entropy string (${ent.toFixed(2)} bits/char): "${truncate(node.value, 50)}"`,
          file: f.path, line: node.loc?.start?.line ?? 0, code: node.value,
        });
      },

      TemplateLiteral(node: any) {
        for (const q of node.quasis) {
          const val = q.value?.raw || q.value?.cooked || '';
          if (val.length < MIN_LEN) continue;
          if (isBenign(val)) continue;
          const ent = shannonEntropy(val);
          if (ent < THRESHOLD) continue;

          findings.push({
            type: 'obfuscation',
            severity: ent >= DANGER_THRESHOLD ? 'danger' : 'warning',
            message: `High entropy template (${ent.toFixed(2)} bits/char): "${truncate(val, 50)}"`,
            file: f.path, line: q.loc?.start?.line ?? 0, code: val,
          });
        }
      },
    });
  }
  return findings;
}
