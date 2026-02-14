import { Command } from 'commander';
import ora from 'ora';
import { scan } from './scanner.ts';
import { printReport } from './reporter.ts';

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
  .option('--fail-on <level>', 'exit 1 if risk >= level (safe|low|medium|high|critical)', 'high')
  .action(async (target: string, opts: { json?: boolean; failOn?: string }) => {
    const spinner = opts.json ? null : ora(`Scanning ${target}...`).start();

    const result = await scan(target);

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

program.parse();
