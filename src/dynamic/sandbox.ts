import * as fs from 'fs';
import * as path from 'path';
import type { DynamicResult, Finding } from '../types.ts';

const IMAGE = 'unsus-sandbox';
const DOCKER_DIR = path.join(import.meta.dir, '../../docker');

export async function ensureImage() {
  const check = Bun.spawnSync(['docker', 'image', 'inspect', IMAGE], { stdout: 'pipe', stderr: 'pipe' });
  if (check.exitCode === 0) return;

  console.error('[*] Building sandbox image (first time)...');
  const build = Bun.spawnSync(['docker', 'build', '-t', IMAGE, DOCKER_DIR], {
    stdout: 'inherit', stderr: 'inherit',
  });
  if (build.exitCode !== 0) throw new Error('Failed to build sandbox image');
}

export async function runDynamic(pkgPath: string, timeout = 30): Promise<{ result: DynamicResult; findings: Finding[] }> {
  await ensureImage();

  const absPath = path.resolve(pkgPath);
  const outDir = `/tmp/unsus-run-${Date.now()}`;
  fs.mkdirSync(path.join(outDir, 'output'), { recursive: true });

  // shared volume for workspace (container 1 writes, container 2 reads)
  const volName = `unsus-ws-${Date.now()}`;
  Bun.spawnSync(['docker', 'volume', 'create', volName], { stdout: 'pipe', stderr: 'pipe' });

  try {
    // --- Container 1: fetch deps (has network, no scripts) ---
    const fetchName = `unsus-fetch-${Date.now()}`;
    const fetchProc = Bun.spawn([
      'docker', 'run',
      '--name', fetchName,
      '--rm',
      '--read-only',
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',
      '--memory=512m',
      '--cpus=1',
      '--pids-limit=100',
      '--tmpfs=/tmp:rw,noexec,nosuid,size=100m',
      '-v', `${absPath}:/pkg:ro`,
      '-v', `${volName}:/workspace`,
      '-v', `${path.join(outDir, 'output')}:/output`,
      '--entrypoint', '/entrypoint-fetch.sh',
      IMAGE,
    ], { stdout: 'pipe', stderr: 'pipe' });

    // timeout for fetch
    let fetchTimedOut = false;
    const fetchTimer = setTimeout(() => {
      fetchTimedOut = true;
      Bun.spawnSync(['docker', 'kill', fetchName], { stdout: 'pipe', stderr: 'pipe' });
    }, timeout * 1000);

    await fetchProc.exited;
    clearTimeout(fetchTimer);

    if (fetchTimedOut) {
      console.error('[!] Fetch container timed out');
    }

    // --- Container 2: run scripts (NO network, strace) ---
    const runName = `unsus-run-${Date.now()}`;
    const runProc = Bun.spawn([
      'docker', 'run',
      '--name', runName,
      '--rm',
      '--network=none',
      '--read-only',
      '--cap-drop=ALL',
      '--cap-add=SYS_PTRACE',
      '--security-opt=no-new-privileges',
      '--memory=512m',
      '--cpus=1',
      '--pids-limit=100',
      '--tmpfs=/tmp:rw,noexec,nosuid,size=50m',
      '-v', `${volName}:/workspace`,
      '-v', `${path.join(outDir, 'output')}:/output`,
      '--entrypoint', '/entrypoint-run.sh',
      IMAGE,
    ], { stdout: 'pipe', stderr: 'pipe' });

    let runTimedOut = false;
    const runTimer = setTimeout(() => {
      runTimedOut = true;
      Bun.spawnSync(['docker', 'kill', runName], { stdout: 'pipe', stderr: 'pipe' });
    }, timeout * 1000);

    await runProc.exited;
    clearTimeout(runTimer);

    // read results
    const result = parseOutput(outDir, runTimedOut);
    return { result, findings: dynamicFindings(result) };

  } finally {
    // cleanup volume
    Bun.spawnSync(['docker', 'volume', 'rm', '-f', volName], { stdout: 'pipe', stderr: 'pipe' });
    try { fs.rmSync(outDir, { recursive: true, force: true }); } catch {}
  }
}

function readFile(p: string): string {
  try { return fs.readFileSync(p, 'utf-8'); } catch { return ''; }
}

function parseOutput(outDir: string, timedOut: boolean): DynamicResult {
  const base = path.join(outDir, 'output');

  // meta.json
  let meta = { exitCode: -1, duration: 0, timedOut };
  try { meta = { ...meta, ...JSON.parse(readFile(path.join(base, 'meta.json'))) }; } catch {}

  // network attempts from strace
  const netRaw = readFile(path.join(base, 'network.log')).trim();
  const networkAttempts = netRaw
    ? netRaw.split('\n').filter(Boolean).map(line => {
        const [ip, port] = line.split(':');
        return { domain: ip!, port: port || '0', raw: line };
      })
    : [];

  // resource samples
  const csvRaw = readFile(path.join(base, 'resources.csv')).trim();
  const resourceSamples = csvRaw
    ? csvRaw.split('\n').slice(1).filter(Boolean).map(line => {
        const [ts, cpu, mem] = line.split(',');
        return { ts: parseInt(ts!, 10), cpu: parseFloat(cpu!), mem: parseFloat(mem!) };
      }).filter(s => !isNaN(s.ts))
    : [];

  // fs changes
  const fsRaw = readFile(path.join(base, 'fs-changes.log')).trim();
  const fsChanges = fsRaw ? fsRaw.split('\n').filter(Boolean) : [];

  const stdout = readFile(path.join(base, 'install.log'));

  return {
    networkAttempts,
    resourceSamples,
    fsChanges,
    installExit: meta.exitCode,
    installDuration: meta.duration,
    timedOut: timedOut || meta.timedOut,
    stdout,
  };
}

function dynamicFindings(r: DynamicResult): Finding[] {
  const out: Finding[] = [];

  // network attempts (strace catches connect() even with --network=none)
  const seen = new Set<string>();
  for (const n of r.networkAttempts) {
    if (seen.has(n.domain)) continue;
    seen.add(n.domain);
    out.push({
      type: 'dynamic-network', severity: 'danger',
      message: `Outbound connection attempted: ${n.domain}:${n.port}`,
      file: 'dynamic-analysis', line: 0, code: n.raw,
    });
  }

  // resource spikes
  if (r.resourceSamples.length > 2) {
    const avg = r.resourceSamples.reduce((s, x) => s + x.cpu, 0) / r.resourceSamples.length;
    const peak = Math.max(...r.resourceSamples.map(x => x.cpu));

    if (avg > 50) {
      out.push({
        type: 'dynamic-resource', severity: 'critical',
        message: `Avg CPU ${avg.toFixed(0)}% during install — cryptominer behavior`,
        file: 'dynamic-analysis', line: 0, code: `avg=${avg.toFixed(1)}% peak=${peak.toFixed(1)}%`,
      });
    } else if (avg > 25) {
      out.push({
        type: 'dynamic-resource', severity: 'warning',
        message: `Elevated CPU ${avg.toFixed(0)}% during install`,
        file: 'dynamic-analysis', line: 0, code: `avg=${avg.toFixed(1)}% peak=${peak.toFixed(1)}%`,
      });
    }
  }

  // suspicious new files (outside node_modules)
  const suspicious = r.fsChanges.filter(f => !f.includes('node_modules') && !f.includes('package-lock'));
  for (const f of suspicious.slice(0, 5)) {
    out.push({
      type: 'dynamic-fs', severity: 'warning',
      message: `New file created during install: ${f}`,
      file: 'dynamic-analysis', line: 0, code: f,
    });
  }

  // timeout
  if (r.timedOut) {
    out.push({
      type: 'dynamic-resource', severity: 'danger',
      message: `Install timed out — possible infinite loop or hanging process`,
      file: 'dynamic-analysis', line: 0, code: '',
    });
  }

  return out;
}
