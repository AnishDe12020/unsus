import * as fs from 'fs';
import * as path from 'path';
import type { ScanResult, Finding } from '../types.ts';

function hasClaudeCLI(): boolean {
  const result = Bun.spawnSync(['which', 'claude'], { stdout: 'pipe', stderr: 'pipe' });
  return result.exitCode === 0;
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
    // try to extract the script filename
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
      // for big files, include first 4000 chars
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

  return `You are an expert npm supply chain security analyst. You are reviewing a package that an automated scanner has flagged.

Your job is to conduct an INDEPENDENT analysis. The scanner is noisy and produces false positives. You must read the actual code and determine if this package is truly malicious or benign.

## Package: ${result.packageName}@${result.version}
## Automated scanner score: ${result.riskScore}/10 (${result.riskLevel})

${context}

## Your task

1. Read the actual source code above independently
2. Look for REAL malicious patterns: data exfiltration, backdoors, cryptominers, credential theft, reverse shells, unauthorized network calls during install
3. Distinguish legitimate library behavior from malicious behavior
4. Give YOUR OWN risk score from 0-10, independent of the scanner

## Response format (follow exactly)

ANALYSIS:
[Your independent analysis — what does this code actually do? Any real threats?]

AI_SCORE: [number 0-10]
AI_VERDICT: [SAFE|SUSPICIOUS|MALICIOUS]

Scoring guide:
- 0-1: Clean, no concerns
- 2-3: Minor concerns but likely benign
- 4-5: Suspicious patterns worth investigating
- 6-7: Likely malicious, multiple red flags
- 8-10: Confirmed malicious behavior`;
}

export interface AIAnalysis {
  verdict: 'safe' | 'suspicious' | 'malicious' | 'skipped';
  aiScore: number | null;
  analysis: string;
  reason: string;
}

export async function analyzeWithAI(
  result: ScanResult,
  pkgDir: string,
  opts?: { force?: boolean }
): Promise<AIAnalysis> {
  if (result.findings.length === 0) {
    return { verdict: 'safe', aiScore: 0, analysis: '', reason: 'No findings to analyze' };
  }

  const hasSeriousFindings = result.findings.some(f => f.severity === 'danger' || f.severity === 'critical');
  if (!opts?.force && result.riskScore <= 0.5 && !hasSeriousFindings) {
    return { verdict: 'safe', aiScore: null, analysis: '', reason: 'Score too low to warrant AI analysis' };
  }

  if (!hasClaudeCLI()) {
    return { verdict: 'skipped', aiScore: null, analysis: '', reason: 'Claude CLI not installed' };
  }

  const prompt = buildPrompt(result, pkgDir);
  if (!prompt) {
    return { verdict: 'safe', aiScore: null, analysis: '', reason: 'No code context to analyze' };
  }

  try {
    const proc = Bun.spawn(
      ['claude', '-p', '--output-format', 'text', prompt],
      { stdout: 'pipe', stderr: 'pipe' }
    );

    const output = await new Response(proc.stdout).text();
    await proc.exited;

    if (proc.exitCode !== 0) {
      const stderr = await new Response(proc.stderr).text();
      return { verdict: 'skipped', aiScore: null, analysis: '', reason: `Claude CLI error: ${stderr.slice(0, 200)}` };
    }

    const text = output.trim();

    // parse structured response
    let verdict: AIAnalysis['verdict'] = 'suspicious';
    let aiScore: number | null = null;

    for (const line of text.split('\n')) {
      const l = line.trim();

      // AI_SCORE: 2.5
      const scoreMatch = l.match(/^AI_SCORE\s*:\s*([\d.]+)/i);
      if (scoreMatch) {
        aiScore = Math.min(10, Math.max(0, parseFloat(scoreMatch[1]!)));
      }

      // AI_VERDICT: SAFE
      const verdictMatch = l.match(/^AI_VERDICT\s*:\s*(\w+)/i);
      if (verdictMatch) {
        const v = verdictMatch[1]!.toLowerCase();
        if (v === 'safe') verdict = 'safe';
        else if (v === 'malicious') verdict = 'malicious';
        else verdict = 'suspicious';
      }
    }

    // extract just the analysis text (between ANALYSIS: and AI_SCORE:)
    const analysisMatch = text.match(/ANALYSIS:\s*\n([\s\S]*?)(?=\nAI_SCORE:|\nAI_VERDICT:|$)/i);
    const analysis = analysisMatch ? analysisMatch[1]!.trim() : text;

    return {
      verdict,
      aiScore,
      analysis,
      reason: `AI analysis triggered (scanner: ${result.riskScore}/10, AI: ${aiScore !== null ? aiScore + '/10' : 'N/A'})`,
    };
  } catch (e: any) {
    return { verdict: 'skipped', aiScore: null, analysis: '', reason: `Failed to run claude: ${e.message}` };
  }
}
