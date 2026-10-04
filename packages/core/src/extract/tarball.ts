import { promises as fs, createReadStream, createWriteStream } from "node:fs";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import os from "node:os";
import path from "node:path";

import * as tar from "tar";

import type { ExtractedPackage, PackageIdentity } from "../types.js";
import { extractLocalPackage } from "./local.js";

export interface ExtractTarballOptions {
  identity?: PackageIdentity;
  maxExtractedBytes?: number;
  maxEntries?: number;
}

export async function extractTarballPackage(
  tarballPath: string,
  options: ExtractTarballOptions = {}
): Promise<ExtractedPackage> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-extract-"));
  try {
    if ((await fs.stat(tarballPath)).size > 20 * 1024 * 1024) throw new Error("Archive exceeds compressed byte limit.");
    const archivePath = path.join(tempDir, "archive.tar");
    const packageRoot = path.join(tempDir, "package");
    await fs.mkdir(packageRoot);
    const handle = await fs.open(tarballPath, "r");
    const magic = Buffer.alloc(2);
    try { await handle.read(magic, 0, 2, 0); } finally { await handle.close(); }
    let inflated = 0;
    const bound = new Transform({ transform(chunk: Buffer, _encoding, callback) {
      inflated += chunk.length;
      callback(inflated > (options.maxExtractedBytes ?? 100 * 1024 * 1024) ? new Error("Archive exceeds decompression byte limit.") : null, chunk);
    } });
    const input = createReadStream(tarballPath);
    if (magic[0] === 0x1f && magic[1] === 0x8b) await pipeline(input, createGunzip(), bound, createWriteStream(archivePath));
    else await pipeline(input, bound, createWriteStream(archivePath));
    let size = 0;
    let entries = 0;
    let topLevel: string | undefined;
    const seen = new Set<string>();
    // Validate every header before writing anything. Reject instead of silently skipping.
    tar.t({ file: archivePath, sync: true, strict: true, onReadEntry: (entry) => {
      if (!isSafeTarPath(entry.path)) throw new Error(`Unsafe archive path: ${entry.path}`);
      if (!["File", "Directory"].includes(entry.type)) throw new Error(`Unsupported archive entry type: ${entry.type} (links are forbidden).`);
      const parts = entry.path.split("/").filter(Boolean);
      topLevel ??= parts[0];
      if (parts[0] !== topLevel || (parts.length === 1 && entry.type !== "Directory")) throw new Error("Archive must contain a single package root directory.");
      const normalized = parts.join("/").normalize("NFC").toLowerCase();
      if (seen.has(normalized)) throw new Error("Duplicate or case-colliding archive path.");
      seen.add(normalized);
      size += entry.size;
      entries += 1;
      if (entry.size > 10 * 1024 * 1024 || size > (options.maxExtractedBytes ?? 100 * 1024 * 1024) || entries > (options.maxEntries ?? 10_000)) throw new Error("Archive exceeds extraction limit.");
    } });
    tar.x({ file: archivePath, cwd: packageRoot, strip: 1, sync: true, strict: true, noChmod: true, noMtime: true });
    const extracted = await extractLocalPackage(packageRoot);
    return {
      ...extracted,
      identity: { ...extracted.identity, ...options.identity },
      isLocal: false,
      cleanup: async () => { await fs.rm(tempDir, { recursive: true, force: true }); }
    };
  } catch (error) {
    await fs.rm(tempDir, { recursive: true, force: true });
    throw error;
  }
}

export function isSafeTarPath(entryPath: string): boolean {
  return entryPath.length > 0 && entryPath.length <= 1024 &&
    !path.posix.isAbsolute(entryPath) && !path.win32.isAbsolute(entryPath) &&
    !entryPath.includes("\\") && !entryPath.includes("\0") &&
    !entryPath.split("/").some((part) => part === ".." || part === "." || part.includes(":"));
}
