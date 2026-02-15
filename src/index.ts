import * as fs from 'fs';
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { scan } from './scanner.ts';
import { printReport } from './reporter.ts';
import { fetchPackage } from './npm.ts';

const LEVEL_ORDER = ['safe', 'low', 'medium', 'high', 'critical'];

const program = new Command();

program
  .name('unsus')
  .description('npm supply chain malware detector')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan a package directory for malicious patterns')
  .argument('<target>', 'path to package directory')
  .option('--json', 'raw JSON output')
  .option('--no-dynamic', 'skip dynamic analysis (Docker sandbox)')
  .option('--fail-on <level>', 'exit 1 if risk >= level (safe|low|medium|high|critical)', 'high')
  .action(async (target: string, opts: { json?: boolean; dynamic?: boolean; failOn?: string }) => {
    const spinner = opts.json ? null : ora(`Scanning ${target}...`).start();

    if (opts.dynamic && spinner) spinner.text = 'Static analysis...';
    const result = await scan(target, { dynamic: opts.dynamic !== false });

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      spinner?.stop();
      printReport(result);
    }

    // CI exit code
    const threshold = LEVEL_ORDER.indexOf(opts.failOn || 'high');
    const actual = LEVEL_ORDER.indexOf(result.riskLevel);
    if (threshold >= 0 && actual >= threshold) process.exit(1);
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
  .option('--fail-on <level>', 'block install if risk >= level', 'high')
  .option('--dry-run', 'scan only, do not install')
  .option('--json', 'JSON output')
  .action(async (packages: string[], opts: {
    pm?: string; dynamic?: boolean; failOn?: string; dryRun?: boolean; json?: boolean;
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

        if (opts.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          spinner?.stop();
          printReport(result);
        }

        const actual = LEVEL_ORDER.indexOf(result.riskLevel);
        if (threshold >= 0 && actual >= threshold) {
          blocked.push(`${pkg} (${result.riskLevel} ${result.riskScore.toFixed(1)}/10)`);
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
