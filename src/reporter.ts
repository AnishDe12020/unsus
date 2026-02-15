import chalk from 'chalk';
import boxen from 'boxen';
import Table from 'cli-table3';
import type { ScanResult } from './types.ts';
import type { AIAnalysis } from './analyzers/llm.ts';
import { truncate } from './utils.ts';

const levelColor: Record<string, (s: string) => string> = {
  safe: chalk.green, low: chalk.blue, medium: chalk.yellow,
  high: chalk.hex('#ff8800'), critical: chalk.red,
};

const sevColor: Record<string, (s: string) => string> = {
  critical: chalk.red, danger: chalk.hex('#ff8800'),
  warning: chalk.yellow, info: chalk.dim,
};

function riskBar(score: number, level: string) {
  const filled = Math.round(score);
  const empty = 10 - filled;
  const color = levelColor[level] || chalk.white;
  return color('█'.repeat(filled)) + chalk.dim('░'.repeat(empty));
}

export function printReport(r: ScanResult) {
  const color = levelColor[r.riskLevel] || chalk.white;

  const header = [
    '',
    chalk.bold(`📦 ${r.packageName}@${r.version}`),
    `Risk: ${riskBar(r.riskScore, r.riskLevel)} ${color(chalk.bold(`${r.riskScore.toFixed(1)}/10 ${r.riskLevel.toUpperCase()}`))}`,
    r.summary,
    '',
  ].join('\n');

  console.log(boxen(header, {
    padding: { left: 1, right: 1, top: 0, bottom: 0 },
    borderStyle: 'round',
    borderColor: r.riskScore >= 7.5 ? 'red' : r.riskScore >= 5 ? 'yellow' : 'green',
  }));

  if (r.findings.length) {
    console.log();
    console.log(chalk.bold(`  Findings (${r.findings.length}):`));
    for (const f of r.findings) {
      const sc = sevColor[f.severity] || chalk.dim;
      const tag = sc(f.severity.toUpperCase().padEnd(8));
      console.log(`  ${tag}  ${f.message}`);
      if (f.file) console.log(`            ${chalk.dim(f.file + (f.line ? ':' + f.line : ''))}`);
    }
  }

  if (r.iocs.length) {
    console.log();
    console.log(chalk.bold(`  IOCs (${r.iocs.length}):`));
    const table = new Table({
      head: ['Type', 'Value', 'Location'].map(h => chalk.dim(h)),
      style: { head: [], border: ['dim'] },
      chars: {
        'top': '─', 'top-mid': '┬', 'top-left': '┌', 'top-right': '┐',
        'bottom': '─', 'bottom-mid': '┴', 'bottom-left': '└', 'bottom-right': '┘',
        'left': '│', 'left-mid': '├', 'mid': '─', 'mid-mid': '┼',
        'right': '│', 'right-mid': '┤', 'middle': '│',
      },
    });
    for (const ioc of r.iocs) {
      const val = ioc.threatMatch
        ? chalk.red(truncate(ioc.value, 42)) + chalk.red(` [${ioc.threatMatch.source}]`)
        : truncate(ioc.value, 48);
      table.push([ioc.type, val, ioc.context]);
    }
    console.log(table.toString().split('\n').map(l => '  ' + l).join('\n'));
  }

  if (r.dynamicAnalysis) {
    const d = r.dynamicAnalysis;
    console.log();
    console.log(chalk.bold('  Dynamic Analysis (Docker sandbox):'));

    const status = d.timedOut
      ? chalk.red('TIMED OUT')
      : d.installExit === 0
        ? chalk.green('OK')
        : chalk.yellow(`exit ${d.installExit}`);
    console.log(`  Install: ${status}  ${chalk.dim(`${d.installDuration}s`)}`);

    if (d.networkAttempts.length) {
      console.log(`  ${chalk.hex('#ff8800')(`${d.networkAttempts.length} outbound request(s) blocked:`)}`);
      for (const n of d.networkAttempts.slice(0, 10)) {
        console.log(`    ${chalk.red('→')} ${n.domain}  ${chalk.dim(n.raw)}`);
      }
      if (d.networkAttempts.length > 10) console.log(chalk.dim(`    ... and ${d.networkAttempts.length - 10} more`));
    }

    if (d.resourceSamples.length > 2) {
      const avgCpu = d.resourceSamples.reduce((s, x) => s + x.cpu, 0) / d.resourceSamples.length;
      const peakCpu = Math.max(...d.resourceSamples.map(x => x.cpu));
      const peakMem = Math.max(...d.resourceSamples.map(x => x.mem));
      const cpuColor = avgCpu > 50 ? chalk.red : avgCpu > 25 ? chalk.yellow : chalk.green;
      console.log(`  CPU: ${cpuColor(`avg ${avgCpu.toFixed(0)}%`)} / peak ${peakCpu.toFixed(0)}%  ${chalk.dim(`mem peak ${peakMem.toFixed(0)}MB`)}`);
    }

    const suspicious = d.fsChanges.filter(f => !f.includes('node_modules') && !f.includes('package-lock'));
    if (suspicious.length) {
      console.log(`  ${chalk.yellow(`${suspicious.length} file(s) created outside node_modules:`)}`);
      for (const f of suspicious.slice(0, 5)) {
        console.log(`    ${chalk.dim(f)}`);
      }
      if (suspicious.length > 5) console.log(chalk.dim(`    ... and ${suspicious.length - 5} more`));
    }
  }

  console.log();
}

const verdictStyle: Record<string, { color: (s: string) => string; label: string }> = {
  safe: { color: chalk.green, label: 'SAFE' },
  suspicious: { color: chalk.yellow, label: 'SUSPICIOUS' },
  malicious: { color: chalk.red, label: 'MALICIOUS' },
  skipped: { color: chalk.dim, label: 'SKIPPED' },
};

export function printAIAnalysis(ai: AIAnalysis, scannerScore?: number, finalScore?: number, finalLevel?: string) {
  if (ai.verdict === 'skipped' && !ai.analysis) {
    if (ai.reason.includes('too low')) return;
    console.log(chalk.dim(`  AI: ${ai.reason}`));
    return;
  }

  if (ai.verdict === 'safe' && !ai.analysis) return;

  const style = verdictStyle[ai.verdict] || verdictStyle.skipped!;
  const providerTag = ai.provider ? ` (${ai.provider[0]!.toUpperCase() + ai.provider.slice(1)})` : '';

  const header: string[] = [
    chalk.bold(`AI Verdict${providerTag}: ${style.color(style.label)}`),
  ];

  if (ai.aiScore !== null && scannerScore !== undefined) {
    const scoreColor = (s: number) => s <= 1 ? chalk.green : s <= 3 ? chalk.blue : s <= 5 ? chalk.yellow : chalk.red;
    header.push(`Scanner: ${scoreColor(scannerScore)(scannerScore + '/10')}  AI: ${scoreColor(ai.aiScore)(ai.aiScore + '/10')}`);
  }

  if (finalScore !== undefined && finalLevel) {
    const finalColor = finalScore <= 1 ? chalk.green : finalScore <= 3 ? chalk.blue : finalScore <= 5 ? chalk.yellow : finalScore <= 7.5 ? chalk.hex('#ff8800') : chalk.red;
    header.push(chalk.bold(`Final Score: ${finalColor(`${finalScore}/10 ${finalLevel.toUpperCase()}`)}`));
  }

  header.push('');
  header.push(ai.analysis);

  console.log(boxen(header.join('\n'), {
    padding: { left: 1, right: 1, top: 0, bottom: 0 },
    borderStyle: 'round',
    borderColor: ai.verdict === 'malicious' ? 'red' : ai.verdict === 'suspicious' ? 'yellow' : 'green',
  }));
  console.log();
}
