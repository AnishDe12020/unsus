import { randomUUID } from "node:crypto";
import { lstat, open, rename, rm } from "node:fs/promises";
import path from "node:path";

/** Replace a report only after the complete new bytes are written, in the same filesystem. */
export async function writeReport(output: string | undefined, report: string): Promise<void> {
  if (output === undefined) {
    process.stdout.write(report);
    return;
  }
  const destination = path.resolve(output);
  const existing = await lstat(destination).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (existing && !existing.isFile()) throw new Error("Report output must be a regular file, not a directory or symbolic link.");
  const temporary = path.join(path.dirname(destination), `.unsus-report-${randomUUID()}.tmp`);
  try {
    const handle = await open(temporary, "wx", existing ? existing.mode & 0o777 : 0o600);
    try { await handle.writeFile(report, "utf8"); await handle.sync(); }
    finally { await handle.close(); }
    await rename(temporary, destination);
  } finally { await rm(temporary, { force: true }); }
}
