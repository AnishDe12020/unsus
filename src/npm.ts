import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import pacote from 'pacote';

export async function fetchPackage(name: string): Promise<{ dir: string; cleanup: () => void }> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'unsus-'));
  const dir = path.join(tmp, 'package');

  await pacote.extract(name, dir);

  return {
    dir,
    cleanup: () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} },
  };
}
