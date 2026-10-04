// Exercise the same packed and extracted artifact users download, then remove it.
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { packageRelease } from './package-release.mjs';
const root = await mkdtemp(path.join(os.tmpdir(), 'unsus-verify-'));
try { await packageRelease(root); }
finally { await rm(root, { recursive: true, force: true }); }
