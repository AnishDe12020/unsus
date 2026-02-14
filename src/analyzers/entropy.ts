import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import type { Finding } from '../types.ts';
import { shannonEntropy, truncate } from '../utils.ts';

const THRESHOLD = 4.5; // normal code ~3-4, base64 ~5.17, obfuscated ~5-6+
const MIN_LEN = 12;

export function analyzeEntropy(files: { path: string; content: string }[]): Finding[] {
  const findings: Finding[] = [];

  for (const f of files) {
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
        const ent = shannonEntropy(node.value);
        if (ent < THRESHOLD) return;

        findings.push({
          type: 'obfuscation',
          severity: ent >= 5.5 ? 'danger' : 'warning',
          message: `High entropy string (${ent.toFixed(2)} bits/char): "${truncate(node.value, 50)}"`,
          file: f.path, line: node.loc?.start?.line ?? 0, code: node.value,
        });
      },

      TemplateLiteral(node: any) {
        for (const q of node.quasis) {
          const val = q.value?.raw || q.value?.cooked || '';
          if (val.length < MIN_LEN) continue;
          const ent = shannonEntropy(val);
          if (ent < THRESHOLD) continue;

          findings.push({
            type: 'obfuscation',
            severity: ent >= 5.5 ? 'danger' : 'warning',
            message: `High entropy template (${ent.toFixed(2)} bits/char): "${truncate(val, 50)}"`,
            file: f.path, line: q.loc?.start?.line ?? 0, code: val,
          });
        }
      },
    });
  }
  return findings;
}
