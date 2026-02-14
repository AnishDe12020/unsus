import type { Finding, PackageFiles } from '../types.ts';

const MAGIC: [string, Buffer][] = [
  ['ELF', Buffer.from([0x7f, 0x45, 0x4c, 0x46])],
  ['PE/MZ', Buffer.from([0x4d, 0x5a])],
  ['Mach-O', Buffer.from([0xfe, 0xed, 0xfa, 0xce])],
  ['Mach-O', Buffer.from([0xfe, 0xed, 0xfa, 0xcf])],
  ['Mach-O', Buffer.from([0xce, 0xfa, 0xed, 0xfe])],
  ['Mach-O', Buffer.from([0xcf, 0xfa, 0xed, 0xfe])],
  ['Mach-O fat', Buffer.from([0xca, 0xfe, 0xba, 0xbe])],
];

const MINER_BINS = [
  'xmrig', 'ccminer', 'cgminer', 'cpuminer', 'minerd', 'ethminer',
  'nbminer', 'phoenixminer', 'gminer', 'lolminer', 't-rex', 'bfgminer',
];

const POOL_DOMAINS = [
  'pool.minexmr.com', 'xmrpool.eu', 'monerohash.com', 'moneroocean.stream',
  'pool.supportxmr.com', 'hashvault.pro', 'nanopool.org', 'herominers.com',
  '2miners.com', 'f2pool.com', 'nicehash.com', 'unmineable.com',
  'minergate.com', 'antpool.com', 'viabtc.com', 'ethermine.org',
];

const STRATUM_RE = /stratum\+?(tcp|ssl|tls)?:\/\//i;

const RESOURCE_PATTERNS = [
  { re: /os\.cpus\(\)/g, msg: 'os.cpus() — CPU enumeration' },
  { re: /navigator\.hardwareConcurrency/g, msg: 'hardwareConcurrency check' },
  { re: /worker_threads/g, msg: 'worker_threads usage' },
  { re: /WebAssembly\.(instantiate|compile)/g, msg: 'WebAssembly loading' },
];

export function analyzeBinaries(pkg: PackageFiles): Finding[] {
  const findings: Finding[] = [];

  for (const bin of pkg.binaryFiles) {
    for (const [name, magic] of MAGIC) {
      if (bin.header.subarray(0, magic.length).equals(magic)) {
        findings.push({
          type: 'binary-suspicious', severity: 'danger',
          message: `${name} binary in package: ${bin.path}`,
          file: bin.path, line: 0, code: '',
        });
        break;
      }
    }

    const lower = bin.path.toLowerCase();
    for (const m of MINER_BINS) {
      if (lower.includes(m)) {
        findings.push({
          type: 'cryptominer', severity: 'critical',
          message: `Known miner binary "${m}" found: ${bin.path}`,
          file: bin.path, line: 0, code: '',
        });
        break;
      }
    }
  }

  // check source for mining stuff
  for (const f of pkg.jsFiles) {
    const src = f.content;

    for (const pool of POOL_DOMAINS) {
      const idx = src.indexOf(pool);
      if (idx !== -1) {
        const ln = countLines(src, idx);
        findings.push({
          type: 'cryptominer', severity: 'critical',
          message: `Mining pool domain: ${pool}`,
          file: f.path, line: ln, code: pool,
        });
      }
    }

    const sm = STRATUM_RE.exec(src);
    if (sm) {
      findings.push({
        type: 'cryptominer', severity: 'critical',
        message: `Stratum mining protocol URL`,
        file: f.path, line: countLines(src, sm.index), code: src.slice(sm.index, sm.index + 60),
      });
    }

    for (const m of MINER_BINS) {
      const idx = src.indexOf(m);
      if (idx !== -1) {
        findings.push({
          type: 'cryptominer', severity: 'danger',
          message: `Reference to miner "${m}" in source`,
          file: f.path, line: countLines(src, idx), code: src.slice(Math.max(0, idx - 20), idx + m.length + 20),
        });
      }
    }

    for (const { re, msg } of RESOURCE_PATTERNS) {
      const regex = new RegExp(re.source, re.flags);
      const rm = regex.exec(src);
      if (rm) {
        findings.push({
          type: 'cryptominer', severity: 'warning',
          message: msg,
          file: f.path, line: countLines(src, rm.index), code: src.slice(rm.index, rm.index + 40),
        });
      }
    }
  }

  return findings;
}

function countLines(src: string, idx: number) {
  let ln = 1;
  for (let i = 0; i < idx && i < src.length; i++) if (src[i] === '\n') ln++;
  return ln;
}
