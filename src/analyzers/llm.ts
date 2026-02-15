import * as fs from 'fs';
import * as path from 'path';
import type { ScanResult, Finding } from '../types.ts';

export type AIProvider = 'claude' | 'gemini' | 'codex';

const PROVIDERS: { name: AIProvider; bin: string; args: (prompt: string) => string[] }[] = [
  { name: 'claude', bin: 'claude', args: (p) => ['claude', '-p', '--output-format', 'text', p] },
  { name: 'gemini', bin: 'gemini', args: (p) => ['gemini', '-p', p] },
  { name: 'codex',  bin: 'codex',  args: (p) => ['codex', 'exec', p] },
];

function isInstalled(bin: string): boolean {
  return Bun.spawnSync(['which', bin], { stdout: 'pipe', stderr: 'pipe' }).exitCode === 0;
}

function detectProvider(preferred?: string): AIProvider | null {
  if (preferred && preferred !== 'auto') {
    const p = PROVIDERS.find(p => p.name === preferred);
    if (p && isInstalled(p.bin)) return p.name;
    return null;
  }
  // auto: first installed wins
  for (const p of PROVIDERS) {
    if (isInstalled(p.bin)) return p.name;
  }
  return null;
}

async function runProvider(provider: AIProvider, prompt: string, timeoutMs = 120_000): Promise<{ output: string; exitCode: number; stderr: string }> {
  const p = PROVIDERS.find(x => x.name === provider)!;
  const proc = Bun.spawn(p.args(prompt), { stdout: 'pipe', stderr: 'pipe' });

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => {
      proc.kill();
      reject(new Error(`${provider} timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs)
  );

  const run = async () => {
    const output = await new Response(proc.stdout).text();
    await proc.exited;
    const stderr = await new Response(proc.stderr).text();
    return { output, exitCode: proc.exitCode ?? 1, stderr };
  };

  return Promise.race([run(), timeout]);
}

/**
 * Read key files from the package for independent AI review.
 * Not just flagged lines — full files that matter.
 */
function gatherPackageContext(result: ScanResult, pkgDir: string): string {
  const sections: string[] = [];

  // 1. package.json (always important)
  try {
    const pkg = fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf-8');
    sections.push(`## package.json\n\`\`\`json\n${pkg.slice(0, 3000)}\n\`\`\``);
  } catch {}

  // 2. install scripts — read the full file if there's a postinstall/preinstall
  const installScriptFinding = result.findings.find(f => f.type === 'install-script');
  if (installScriptFinding) {
    const scriptCmd = installScriptFinding.code || installScriptFinding.message;
    const match = scriptCmd.match(/(?:node|sh|bash)\s+(\S+)/);
    if (match) {
      try {
        const content = fs.readFileSync(path.join(pkgDir, match[1]!), 'utf-8');
        sections.push(`## Install script: ${match[1]}\n\`\`\`js\n${content.slice(0, 5000)}\n\`\`\``);
      } catch {}
    }
  }

  // 3. Read files referenced in findings (full file, not just snippets)
  const filesRead = new Set<string>();
  const interesting = result.findings.filter(f =>
    f.file && f.file !== 'dynamic-analysis' && f.file !== 'unknown' && f.file !== 'package.json'
  );

  for (const f of interesting) {
    if (filesRead.has(f.file) || filesRead.size >= 5) continue;
    filesRead.add(f.file);
    try {
      const content = fs.readFileSync(path.join(pkgDir, f.file), 'utf-8');
      const trimmed = content.length > 4000 ? content.slice(0, 4000) + '\n... (truncated)' : content;
      sections.push(`## ${f.file}\n\`\`\`js\n${trimmed}\n\`\`\``);
    } catch {}
  }

  // 4. Scanner findings summary
  const findingSummary = result.findings
    .map(f => `- [${f.severity.toUpperCase()}] ${f.message} (${f.file}:${f.line})`)
    .join('\n');
  sections.push(`## Scanner findings (${result.findings.length})\n${findingSummary}`);

  // 5. IOCs
  if (result.iocs.length) {
    const iocList = result.iocs.slice(0, 20)
      .map(i => `- ${i.type}: ${i.value} (${i.context})${i.threatMatch ? ` **THREAT INTEL MATCH: ${i.threatMatch.source}**` : ''}`)
      .join('\n');
    sections.push(`## Extracted IOCs\n${iocList}`);
  }

  // 6. Dynamic analysis
  if (result.dynamicAnalysis) {
    const d = result.dynamicAnalysis;
    const dynParts = [`Install: exit ${d.installExit}, ${d.installDuration}s${d.timedOut ? ' (TIMED OUT)' : ''}`];
    if (d.networkAttempts.length) {
      dynParts.push(`Network attempts: ${d.networkAttempts.map(n => `${n.domain}:${n.port}`).join(', ')}`);
    }
    if (d.resourceSamples.length > 2) {
      const avg = d.resourceSamples.reduce((s, x) => s + x.cpu, 0) / d.resourceSamples.length;
      dynParts.push(`CPU: avg ${avg.toFixed(0)}%`);
    }
    if (d.fsChanges.filter(f => !f.includes('node_modules')).length) {
      dynParts.push(`Files created outside node_modules: ${d.fsChanges.filter(f => !f.includes('node_modules')).join(', ')}`);
    }
    sections.push(`## Dynamic analysis (Docker sandbox)\n${dynParts.join('\n')}`);
  }

  return sections.join('\n\n');
}

function buildPrompt(result: ScanResult, pkgDir: string): string {
  const context = gatherPackageContext(result, pkgDir);
  if (!context) return '';

  return `You are an expert npm supply chain security analyst performing triage on a package flagged by an automated scanner.

The scanner is pattern-based and produces many FALSE POSITIVES. Your job is to read the actual code, reason about intent, and determine whether this package is truly malicious or benign. Do NOT parrot the scanner — form your own independent judgment.

## Package under review: ${result.packageName}@${result.version}
## Automated scanner score: ${result.riskScore}/10 (${result.riskLevel})

${context}

## Analysis methodology — follow this order

### Step 1: Package identity
- Is this a well-known, widely-used package (e.g. express, lodash, react)? If so, treat scanner findings with extreme skepticism.
- Does the name look like a typosquat of a popular package (e.g. "expres", "lodashe", "reactt")?
- Does package.json have a plausible repository URL, author, and description?

### Step 2: Install hooks (HIGHEST PRIORITY)
- Does it have preinstall/postinstall/preuninstall scripts?
- Do those scripts execute external code, fetch URLs, or run obfuscated commands?
- Install hooks that run \`node index.js\` for compilation/setup are normal. Install hooks that run \`curl | sh\` or fetch remote payloads are not.

### Step 3: Code behavior analysis
Read the flagged source files and determine what they ACTUALLY do:
- Follow the data flow. Does data leave the machine? Where does it go?
- Is there obfuscation (hex-encoded strings, char code assembly, eval of constructed strings)? Or are "obfuscated-looking" patterns just minified code or standard encodings?
- Are network calls legitimate API functionality (HTTP client libs, database drivers) or covert exfiltration?

### Step 4: Intent assessment
This is the critical question: **Is there evidence of malicious INTENT?**
- Legitimate: A logging library that sends data to a user-configured endpoint
- Malicious: A package that silently collects env vars/SSH keys/credentials and POSTs them to a hardcoded domain during install

## Common false positives — DO NOT flag these as threats
- Base64 usage for encoding/decoding in normal operations (auth headers, data URIs, API payloads)
- Dynamic require() in plugin/loader systems (template engines, test runners, module loaders)
- Network calls in packages whose PURPOSE is networking (HTTP clients, API SDKs, database drivers)
- eval() in parsers, template engines, or REPL implementations
- References to environment variables in configuration/setup code (reading PORT, NODE_ENV, etc.)
- Minified/bundled vendor files that look "obfuscated" but are just build artifacts
- Repository URL strings matching "base64" or "hex" patterns in package.json metadata

## Real malicious indicators — these ARE threats
- Collecting sensitive data (env vars, SSH keys, .npmrc tokens, AWS credentials) and sending them to external servers
- Hardcoded C2 domains or IP addresses that receive exfiltrated data
- Encoded/obfuscated payloads that decode to shell commands or network exfiltration
- DNS-based data exfiltration (encoding stolen data as DNS subdomains)
- Reverse shells or bind shells
- Cryptocurrency miners
- File system writes outside the package directory (e.g. modifying ~/.bashrc, ~/.ssh/)
- Install scripts that download and execute remote code from untrusted sources

## Response format (follow EXACTLY)

ANALYSIS:
[Walk through your reasoning step by step. For each scanner finding, state whether it is a true positive or false positive and why. Then give your overall assessment of the package.]

AI_SCORE: [number 0-10]
AI_VERDICT: [SAFE|SUSPICIOUS|MALICIOUS]

## Scoring guide
- 0.0: Clean, well-known package, all findings are false positives
- 0.5-1.0: Clean, no real concerns, minor scanner noise
- 2.0-3.0: Unusual patterns but explainable — likely benign with minor code smells
- 4.0-5.0: Genuinely suspicious patterns that warrant manual review (but not confirmed malicious)
- 6.0-7.0: Strong indicators of malicious intent — multiple red flags, obfuscation + exfiltration patterns
- 8.0-10.0: Confirmed malicious — clear evidence of data theft, backdoors, or destructive behavior`;
}

export interface AIAnalysis {
  verdict: 'safe' | 'suspicious' | 'malicious' | 'skipped';
  aiScore: number | null;
  analysis: string;
  reason: string;
  provider: AIProvider | null;
}

function parseResponse(text: string): { verdict: AIAnalysis['verdict']; aiScore: number | null; analysis: string } {
  let verdict: AIAnalysis['verdict'] = 'suspicious';
  let aiScore: number | null = null;

  for (const line of text.split('\n')) {
    const l = line.trim();

    const scoreMatch = l.match(/^AI_SCORE\s*:\s*([\d.]+)/i);
    if (scoreMatch) {
      aiScore = Math.min(10, Math.max(0, parseFloat(scoreMatch[1]!)));
    }

    const verdictMatch = l.match(/^AI_VERDICT\s*:\s*(\w+)/i);
    if (verdictMatch) {
      const v = verdictMatch[1]!.toLowerCase();
      if (v === 'safe') verdict = 'safe';
      else if (v === 'malicious') verdict = 'malicious';
      else verdict = 'suspicious';
    }
  }

  const analysisMatch = text.match(/ANALYSIS:\s*\n([\s\S]*?)(?=\nAI_SCORE:|\nAI_VERDICT:|$)/i);
  const analysis = analysisMatch ? analysisMatch[1]!.trim() : text;

  return { verdict, aiScore, analysis };
}

export async function analyzeWithAI(
  result: ScanResult,
  pkgDir: string,
  opts?: { force?: boolean; provider?: string }
): Promise<AIAnalysis> {
  const skip = (reason: string): AIAnalysis => ({ verdict: 'skipped', aiScore: null, analysis: '', reason, provider: null });

  if (result.findings.length === 0) {
    return { verdict: 'safe', aiScore: 0, analysis: '', reason: 'No findings to analyze', provider: null };
  }

  const hasSeriousFindings = result.findings.some(f => f.severity === 'danger' || f.severity === 'critical');
  if (!opts?.force && result.riskScore <= 0.5 && !hasSeriousFindings) {
    return { verdict: 'safe', aiScore: null, analysis: '', reason: 'Score too low to warrant AI analysis', provider: null };
  }

  const provider = detectProvider(opts?.provider);
  if (!provider) {
    const wanted = opts?.provider && opts.provider !== 'auto' ? opts.provider : 'claude/gemini/codex';
    return skip(`No AI CLI found (tried ${wanted}). Install one: claude, gemini, or codex`);
  }

  const prompt = buildPrompt(result, pkgDir);
  if (!prompt) {
    return { verdict: 'safe', aiScore: null, analysis: '', reason: 'No code context to analyze', provider: null };
  }

  try {
    const { output, exitCode, stderr } = await runProvider(provider, prompt);

    if (exitCode !== 0) {
      return skip(`${provider} CLI error: ${stderr.slice(0, 200)}`);
    }

    const { verdict, aiScore, analysis } = parseResponse(output.trim());

    return {
      verdict,
      aiScore,
      analysis,
      reason: `AI analysis via ${provider} (scanner: ${result.riskScore}/10, AI: ${aiScore !== null ? aiScore + '/10' : 'N/A'})`,
      provider,
    };
  } catch (e: any) {
    return skip(`Failed to run ${provider}: ${e.message}`);
  }
}
