import { Command } from 'commander';
import { scan } from './scanner.ts';

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
    const result = await scan(target);

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    // colors
    const R = '\x1b[31m', O = '\x1b[38;5;208m', Y = '\x1b[33m';
    const G = '\x1b[32m', B = '\x1b[34m', DIM = '\x1b[90m';
    const BOLD = '\x1b[1m', RST = '\x1b[0m';

    const levelColor: Record<string, string> = {
      safe: G, low: B, medium: Y, high: O, critical: R,
    };
    const sevColor: Record<string, string> = {
      critical: R, danger: O, warning: Y, info: DIM,
    };

    const c = levelColor[result.riskLevel] || '';
    console.log();
    console.log(`${BOLD}  📦 ${result.packageName}@${result.version}${RST}`);
    console.log(`  Risk: ${c}${BOLD}${result.riskScore.toFixed(1)}/10 ${result.riskLevel.toUpperCase()}${RST}`);
    console.log(`  ${result.summary}`);
    console.log();

    if (result.findings.length) {
      console.log(`${BOLD}  Findings (${result.findings.length}):${RST}`);
      for (const f of result.findings) {
        const sc = sevColor[f.severity] || '';
        const tag = f.severity.toUpperCase().padEnd(8);
        console.log(`  ${sc}${tag}${RST} ${f.message}`);
        if (f.file) console.log(`         ${DIM}${f.file}${f.line ? ':' + f.line : ''}${RST}`);
      }
      console.log();
    }

    if (result.iocs.length) {
      console.log(`${BOLD}  IOCs (${result.iocs.length}):${RST}`);
      for (const ioc of result.iocs) {
        console.log(`  ${ioc.type.padEnd(12)} ${ioc.value}`);
        console.log(`             ${DIM}${ioc.context}${RST}`);
      }
      console.log();
    }
  });

program.parse();
