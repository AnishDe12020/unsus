import * as fs from 'fs';
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { scan } from './scanner.ts';
import { printReport, printAIAnalysis } from './reporter.ts';
import { fetchPackage } from './npm.ts';
import { analyzeWithAI } from './analyzers/llm.ts';

const LEVEL_ORDER = ['safe', 'low', 'medium', 'high', 'critical'];

function toLevel(s: number): string {
  if (s <= 1) return 'safe';
  if (s <= 3) return 'low';
  if (s <= 5) return 'medium';
  if (s <= 7.5) return 'high';
  return 'critical';
}

/**
 * Blend scanner + AI scores into a final score.
 * AI is weighted higher (0.6) because it reads actual code with understanding.
 * Scanner (0.4) provides mechanical pattern coverage the AI might miss.
 * When they agree, confidence is high. When they diverge, AI pulls toward reality.
 */
function computeFinalScore(scannerScore: number, ai: import('./analyzers/llm.ts').AIAnalysis): { finalScore: number; finalLevel: string } {
  if (ai.aiScore === null || ai.verdict === 'skipped') {
    return { finalScore: scannerScore, finalLevel: toLevel(scannerScore) };
  }

  const blended = Math.round((scannerScore * 0.4 + ai.aiScore * 0.6) * 10) / 10;
  const finalScore = Math.min(10, Math.max(0, blended));
  return { finalScore, finalLevel: toLevel(finalScore) };
}

const program = new Command();

program
  .name('unsus')
  .description('npm supply chain malware detector')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan an npm package for malicious patterns')
  .argument('<package>', 'npm package name (e.g. express, lodash@4.17.21)')
  .option('--json', 'raw JSON output')
  .option('--no-dynamic', 'skip dynamic analysis (Docker sandbox)')
  .option('--no-ai', 'skip AI analysis')
  .option('--ai-provider <provider>', 'AI backend: claude|gemini|codex|auto', 'auto')
  .option('--fail-on <level>', 'exit 1 if risk >= level (safe|low|medium|high|critical)', 'high')
  .action(async (pkg: string, opts: { json?: boolean; dynamic?: boolean; ai?: boolean; aiProvider?: string; failOn?: string }) => {
    const isLocal = pkg.startsWith('.') || pkg.startsWith('/') || fs.existsSync(pkg);
    const spinner = opts.json ? null : ora(isLocal ? `Scanning ${pkg}...` : `Fetching ${pkg} from npm...`).start();

    let dir: string;
    let cleanup: (() => void) | undefined;

    if (isLocal) {
      dir = pkg;
    } else {
      try {
        const fetched = await fetchPackage(pkg);
        dir = fetched.dir;
        cleanup = fetched.cleanup;
      } catch (e: any) {
        spinner?.fail(`Failed to fetch ${pkg}: ${e.message}`);
        process.exit(1);
      }
    }

    try {
      if (spinner) spinner.text = `Scanning ${pkg}...`;
      const result = await scan(dir, { dynamic: opts.dynamic !== false });

      let finalScore = result.riskScore;
      let finalLevel = result.riskLevel;

      if (opts.json) {
        if (opts.ai !== false) {
          const ai = await analyzeWithAI(result, dir, { provider: opts.aiProvider });
          const combined = computeFinalScore(result.riskScore, ai);
          finalScore = combined.finalScore;
          finalLevel = combined.finalLevel;
          console.log(JSON.stringify({ ...result, finalScore, finalLevel, aiAnalysis: ai }, null, 2));
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
      } else {
        spinner?.stop();
        printReport(result);

        if (opts.ai !== false) {
          const aiSpinner = ora('Running AI analysis...').start();
          const ai = await analyzeWithAI(result, dir, { provider: opts.aiProvider });
          aiSpinner.stop();
          const combined = computeFinalScore(result.riskScore, ai);
          finalScore = combined.finalScore;
          finalLevel = combined.finalLevel;
          printAIAnalysis(ai, result.riskScore, finalScore, finalLevel);
        }
      }

      const threshold = LEVEL_ORDER.indexOf(opts.failOn || 'high');
      const actual = LEVEL_ORDER.indexOf(finalLevel);
      if (threshold >= 0 && actual >= threshold) process.exit(1);
    } finally {
      cleanup?.();
    }
  });

function detectPM(): string {
  if (fs.existsSync('bun.lock') || fs.existsSync('bun.lockb')) return 'bun';
  if (fs.existsSync('yarn.lock')) return 'yarn';
  if (fs.existsSync('pnpm-lock.yaml')) return 'pnpm';
  return 'npm';
}

function installCmd(pm: string, pkgs: string[]): string[] {
  const cmd = pm === 'npm' ? 'install' : 'add';
  return [pm, cmd, ...pkgs];
}

program
  .command('install')
  .description('Scan npm packages for malware before installing')
  .argument('<packages...>', 'npm packages to install')
  .option('--pm <manager>', 'package manager (bun|npm|yarn|pnpm)')
  .option('--no-dynamic', 'skip dynamic analysis (Docker sandbox)')
  .option('--no-ai', 'skip AI analysis')
  .option('--ai-provider <provider>', 'AI backend: claude|gemini|codex|auto', 'auto')
  .option('--fail-on <level>', 'block install if risk >= level', 'high')
  .option('--dry-run', 'scan only, do not install')
  .option('--json', 'JSON output')
  .action(async (packages: string[], opts: {
    pm?: string; dynamic?: boolean; ai?: boolean; aiProvider?: string; failOn?: string; dryRun?: boolean; json?: boolean;
  }) => {
    const pm = opts.pm || detectPM();
    const threshold = LEVEL_ORDER.indexOf(opts.failOn || 'high');
    const blocked: string[] = [];

    for (const pkg of packages) {
      const spinner = opts.json ? null : ora(`Fetching ${pkg} from npm...`).start();

      let fetched;
      try {
        fetched = await fetchPackage(pkg);
      } catch (e: any) {
        spinner?.fail(`Failed to fetch ${pkg}: ${e.message}`);
        continue;
      }

      try {
        if (spinner) spinner.text = `Scanning ${pkg}...`;
        const result = await scan(fetched.dir, { dynamic: opts.dynamic !== false });

        let finalScore = result.riskScore;
        let finalLevel = result.riskLevel;

        if (opts.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          spinner?.stop();
          printReport(result);

          if (opts.ai !== false) {
            const aiSpinner = ora('Running AI analysis...').start();
            const ai = await analyzeWithAI(result, fetched.dir, { provider: opts.aiProvider });
            aiSpinner.stop();
            const combined = computeFinalScore(result.riskScore, ai);
            finalScore = combined.finalScore;
            finalLevel = combined.finalLevel;
            printAIAnalysis(ai, result.riskScore, finalScore, finalLevel);
          }
        }

        const actual = LEVEL_ORDER.indexOf(finalLevel);
        if (threshold >= 0 && actual >= threshold) {
          blocked.push(`${pkg} (${finalLevel} ${finalScore.toFixed(1)}/10)`);
        }
      } finally {
        fetched.cleanup();
      }
    }

    if (blocked.length) {
      console.log(chalk.red(`\nBlocked ${blocked.length} package(s):`));
      for (const b of blocked) console.log(chalk.red(`  - ${b}`));
      console.log(chalk.dim(`\nThreshold: --fail-on ${opts.failOn || 'high'}`));
      process.exit(1);
    }

    if (opts.dryRun) {
      console.log(chalk.green('\nAll packages passed. (dry run, skipping install)'));
      return;
    }

    // all clear — install
    const cmd = installCmd(pm, packages);
    console.log(chalk.green(`\nAll packages passed. Running: ${cmd.join(' ')}`));
    const proc = Bun.spawn(cmd, { stdout: 'inherit', stderr: 'inherit' });
    const code = await proc.exited;
    if (code !== 0) process.exit(code);
  });

program.parse();
