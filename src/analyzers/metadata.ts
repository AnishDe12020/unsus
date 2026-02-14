import type { Finding, IOC, PackageFiles } from '../types.ts';
import { levenshtein } from '../utils.ts';

// popular packages for typosquat comparison
const POPULAR = [
  'express', 'react', 'vue', 'angular', 'lodash', 'axios', 'chalk',
  'commander', 'debug', 'moment', 'webpack', 'babel', 'eslint',
  'typescript', 'next', 'nuxt', 'jest', 'mocha', 'prettier',
  'underscore', 'request', 'bluebird', 'async', 'rxjs', 'dayjs',
  'dotenv', 'cors', 'uuid', 'mongoose', 'sequelize', 'passport',
  'jsonwebtoken', 'bcrypt', 'nodemailer', 'socket.io', 'redis',
  'pg', 'mysql2', 'puppeteer', 'cheerio', 'yargs', 'inquirer',
  'ora', 'boxen', 'glob', 'rimraf', 'mkdirp', 'semver',
  'colors', 'faker', 'ethers', 'web3', 'hardhat', 'truffle',
];

export function analyzeMetadata(pkg: PackageFiles): { findings: Finding[]; iocs: IOC[] } {
  const findings: Finding[] = [];
  const iocs: IOC[] = [];
  const json = pkg.packageJson;

  for (const hook of ['preinstall', 'postinstall', 'install', 'preuninstall']) {
    const cmd = json.scripts?.[hook];
    if (cmd) {
      findings.push({
        type: 'install-script', severity: 'critical',
        message: `"${hook}" lifecycle script: ${cmd}`,
        file: 'package.json', line: 0,
        code: `"${hook}": "${cmd}"`,
      });
    }
  }

  // base64 in metadata fields
  walkValues(json, '', (val, path) => {
    if (typeof val !== 'string' || val.length < 16) return;
    if (!isBase64ish(val)) return;

    findings.push({
      type: 'metadata-base64', severity: 'danger',
      message: `Possible base64 in ${path}: "${val.length > 60 ? val.slice(0, 60) + '...' : val}"`,
      file: 'package.json', line: 0, code: val,
    });

    // decode it, urls in base64 = extra sus
    try {
      const decoded = Buffer.from(val, 'base64').toString();
      if (/https?:\/\//.test(decoded))
        iocs.push({ type: 'url', value: decoded, context: `package.json ${path}` });
    } catch {}
  });

  // typosquat check
  const name = json.name;
  if (name) {
    for (const pop of POPULAR) {
      if (name === pop) continue;
      const d = levenshtein(name, pop);
      if (d > 0 && d <= 2) {
        findings.push({
          type: 'typosquat', severity: 'danger',
          message: `Name "${name}" looks like "${pop}" (distance ${d})`,
          file: 'package.json', line: 0, code: `"name": "${name}"`,
        });
      }
    }
  }

  return { findings, iocs };
}

function walkValues(obj: any, path: string, cb: (val: any, path: string) => void) {
  if (typeof obj === 'string') return cb(obj, path);
  if (Array.isArray(obj)) return obj.forEach((v, i) => walkValues(v, `${path}[${i}]`, cb));
  if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      // skip dep version strings
      if (['dependencies','devDependencies','peerDependencies'].includes(k)) continue;
      walkValues(v, path ? `${path}.${k}` : k, cb);
    }
  }
}

function isBase64ish(s: string) {
  if (/^[\d.]+$/.test(s)) return false;       // semver
  if (/^https?:\/\//.test(s)) return false;    // url
  if (/\s/.test(s)) return false;              // has whitespace
  return /^[A-Za-z0-9+/]+=*$/.test(s);
}
