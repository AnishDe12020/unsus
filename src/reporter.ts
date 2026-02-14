import chalk from 'chalk';
import boxen from 'boxen';
import Table from 'cli-table3';
import type { ScanResult } from './types.ts';
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
      table.push([ioc.type, truncate(ioc.value, 48), ioc.context]);
    }
    console.log(table.toString().split('\n').map(l => '  ' + l).join('\n'));
  }

  console.log();
}
