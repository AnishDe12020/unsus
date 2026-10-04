// Build first. Packs the publishable workspaces and verifies a clean consumer install.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
const repo = process.cwd();
const root = await mkdtemp(path.join(os.tmpdir(), 'unsus-release-'));
function run(command, args, cwd = repo, statuses = [0]) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', env: process.env });
  assert.ok(statuses.includes(result.status), `${command} ${args.join(' ')}\n${result.stderr}\n${result.stdout}`);
  return result.stdout;
}
try {
  const tarballs = [];
  for (const name of ['core', 'sandbox', 'cli']) {
    const [pack] = JSON.parse(run('npm', ['pack', '--ignore-scripts', '--json', '--workspace', `@unsus/${name}`, '--pack-destination', root]));
    assert.ok(pack.files.some(file => file.path === 'LICENSE'));
    assert.ok(pack.files.some(file => file.path === 'README.md'));
    assert.ok(!pack.files.some(file => /\.test\.|^src\//.test(file.path)), 'Tests and source fixtures must not ship');
    tarballs.push(path.join(root, pack.filename));
    console.log(`${pack.name}@${pack.version}: ${pack.entryCount} entries; ${pack.size} packed bytes; ${pack.integrity}`);
  }
  const consumer = path.join(root, 'consumer');
  await mkdir(consumer);
  await writeFile(path.join(consumer, 'package.json'), '{"name":"unsus-artifact-check","version":"1.0.0","private":true}');
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', ...tarballs], consumer);
  const binary = path.join(consumer, 'node_modules/.bin/unsus');
  assert.match(run(binary, ['--help'], consumer), /guarded npm installer/);
  const fixture = path.join(repo, 'fixtures/benign/normal-package');
  const report = JSON.parse(run(binary, ['scan', fixture, '--json'], consumer));
  assert.equal(report.package.name, 'normal-package');
  assert.equal(report.coverage.dependenciesAnalyzed, false);
  const reportPath = path.join(root, 'report.json');
  await writeFile(reportPath, JSON.stringify(report));
  assert.match(run(binary, ['explain', reportPath], consumer), /normal-package/);
  const diff = JSON.parse(run(binary, ['diff', fixture, '--against', fixture, '--json'], consumer));
  assert.equal(diff.changedFiles.length, 0);
  run(binary, ['scan', path.join(repo, 'fixtures/suspicious/postinstall-env-network')], consumer, [2]);
  const manifest = JSON.parse(await readFile(path.join(consumer, 'node_modules/@unsus/cli/package.json'), 'utf8'));
  assert.equal(manifest.version, '0.1.0');
  console.log('Release artifacts installed into a clean project; help, scan, explain, diff, and blocking exit verified.');
} finally { await rm(root, { recursive: true, force: true }); }
