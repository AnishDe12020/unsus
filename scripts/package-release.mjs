// Build first. Package the compiled CLI and locked pure-JS dependencies for offline use.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { create, extract } from 'tar';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
function run(command, args, cwd, statuses = [0]) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', timeout: 120_000, env: process.env });
  assert.ok(statuses.includes(result.status), `${command} ${args.join(' ')}\n${result.error ?? ''}\n${result.stderr}\n${result.stdout}`);
  return result.stdout;
}

export async function packageRelease(outputDirectory) {
  const { version } = JSON.parse(await readFile(path.join(repo, 'package.json'), 'utf8'));
  assert.match(version, /^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/);
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'unsus-release-'));
  const name = `unsus-${version}`;
  const kit = path.join(scratch, name);
  try {
    const packages = path.join(kit, 'packages');
    const runtime = path.join(kit, 'runtime');
    await mkdir(packages, { recursive: true });
    await mkdir(runtime);
    await mkdir(path.join(kit, 'bin'));
    const dependencies = {};
    for (const workspace of ['core', 'sandbox', 'cli']) {
      const [pack] = JSON.parse(run('npm', ['pack', '--ignore-scripts', '--json', '--workspace', `@unsus/${workspace}`, '--pack-destination', packages], repo));
      assert.equal(pack.version, version, 'Workspace versions must match');
      assert.ok(pack.files.some(file => file.path === 'LICENSE'));
      assert.ok(pack.files.some(file => file.path === 'README.md'));
      assert.ok(!pack.files.some(file => /\.test\.|^src\//.test(file.path)), 'Tests and source fixtures must not ship');
      dependencies[pack.name] = `file:../packages/${pack.filename}`;
    }
    const lock = JSON.parse(await readFile(path.join(repo, 'package-lock.json'), 'utf8'));
    const overrides = Object.fromEntries(Object.entries(lock.packages)
      .filter(([key, value]) => key.startsWith('node_modules/') && !value.dev && !value.link)
      .map(([key, value]) => [key.split('node_modules/').at(-1), value.version]));
    await writeFile(path.join(runtime, 'package.json'), JSON.stringify({ name: 'unsus-portable-runtime', version, private: true, dependencies, overrides }, null, 2) + '\n');
    run('npm', ['install', '--global=false', '--prefix', runtime, '--ignore-scripts', '--no-audit', '--no-fund'], runtime);
    await writeFile(path.join(kit, 'package.json'), JSON.stringify({ name: 'unsus-portable', version, private: true, type: 'module' }) + '\n');
    await writeFile(path.join(kit, 'bin', 'unsus'), "#!/usr/bin/env node\nimport '../runtime/node_modules/@unsus/cli/dist/index.js';\n");
    await chmod(path.join(kit, 'bin', 'unsus'), 0o755);
    await copyFile(path.join(repo, 'LICENSE'), path.join(kit, 'LICENSE'));
    await copyFile(path.join(repo, 'README.md'), path.join(kit, 'README.md'));
    await writeFile(path.join(kit, 'INSTALL.txt'), `unsus ${version}\n\nRequires Node.js 22 or newer. No build, npm install, or network access is needed to run this kit.\nRun: node bin/unsus --help\nmacOS/Linux: ./bin/unsus --help\n\nMove this entire directory somewhere permanent before adding bin/ to PATH or symlinking bin/unsus.\nKeep runtime/ and packages/ with bin/. Third-party licenses remain in runtime/node_modules/.\nRegistry scans and guarded installs still require network access; installs require npm.\nDocker is needed only for explicit dynamic observation.\n`);
    const archive = path.join(scratch, `${name}.tar.gz`);
    await create({ cwd: scratch, file: archive, gzip: true, portable: true }, [name]);
    const extracted = path.join(scratch, 'extracted');
    await mkdir(extracted);
    await extract({ cwd: extracted, file: archive });
    const cli = path.join(extracted, name, 'bin', 'unsus');
    const consumer = path.join(scratch, 'consumer');
    await mkdir(consumer);
    await writeFile(path.join(consumer, 'package.json'), JSON.stringify({ private: true, dependencies: {} }));
    assert.equal(run(process.execPath, [cli, '--version'], consumer).trim(), version);
    const project = JSON.parse(run(process.execPath, [cli, 'project', '.', '--json'], consumer));
    assert.equal(project.kind, 'project');
    assert.equal(project.coverage.declared, 0);
    assert.equal(project.coverage.lockfileVerified, false);
    if (process.platform !== 'win32') {
      const linked = path.join(consumer, 'unsus');
      await symlink(cli, linked);
      assert.equal(run(linked, ['--version'], consumer).trim(), version, 'Launcher must work through a PATH symlink');
    }
    assert.match(run(process.execPath, [cli, 'install', '--help'], consumer), /lifecycle scripts disabled/);
    const fixture = path.join(repo, 'fixtures/benign/normal-package');
    const report = JSON.parse(run(process.execPath, [cli, 'scan', fixture, '--json'], consumer));
    assert.equal(report.package.name, 'normal-package');
    assert.equal(report.coverage.dependenciesAnalyzed, false);
    const sarifPath = path.join(consumer, 'report.sarif');
    assert.equal(run(process.execPath, [cli, 'scan', fixture, '--format', 'sarif', '--output', sarifPath], consumer), '');
    assert.equal(JSON.parse(await readFile(sarifPath, 'utf8')).version, '2.1.0');
    const reportPath = path.join(scratch, 'report.json');
    await writeFile(reportPath, JSON.stringify(report));
    assert.match(run(process.execPath, [cli, 'explain', reportPath], consumer), /normal-package/);
    const diff = JSON.parse(run(process.execPath, [cli, 'diff', fixture, '--against', fixture, '--json'], consumer));
    assert.equal(diff.changedFiles.length, 0);
    run(process.execPath, [cli, 'scan', path.join(repo, 'fixtures/suspicious/postinstall-env-network')], consumer, [2]);
    await mkdir(outputDirectory, { recursive: true });
    const destination = path.join(outputDirectory, path.basename(archive));
    await copyFile(archive, destination);
    const checksum = createHash('sha256').update(await readFile(archive)).digest('hex');
    await writeFile(`${destination}.sha256`, `${checksum}  ${path.basename(archive)}\n`);
    console.log(`Verified extracted ${name}: version, help, scan, explain, diff, and blocking exit.\n${destination}\n${checksum}`);
    return destination;
  } finally { await rm(scratch, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length > 3) throw new Error('Usage: node scripts/package-release.mjs [output-directory]');
  await packageRelease(path.resolve(process.argv[2] ?? path.join(repo, 'artifacts/release')));
}
