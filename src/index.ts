import { Command } from 'commander';
import ora from 'ora';
import { scan } from './scanner.ts';
import { printReport } from './reporter.ts';

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
  .action(async (target: string, opts: { json?: boolean }) => {
    const spinner = opts.json ? null : ora(`Scanning ${target}...`).start();

    const result = await scan(target);

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    spinner?.stop();
    printReport(result);
  });

program.parse();
