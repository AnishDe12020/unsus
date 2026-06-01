import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import * as tar from "tar";

import type { ExtractedPackage, PackageIdentity } from "../types.js";
import { extractLocalPackage } from "./local.js";

export interface ExtractTarballOptions {
  identity?: PackageIdentity;
}

export async function extractTarballPackage(
  tarballPath: string,
  options: ExtractTarballOptions = {}
): Promise<ExtractedPackage> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-extract-"));
  await tar.x({
    file: tarballPath,
    cwd: tempDir,
    strip: 1,
    filter: (entryPath: string) => isSafeTarPath(entryPath)
  });

  const extracted = await extractLocalPackage(tempDir);
  return {
    ...extracted,
    identity: {
      ...extracted.identity,
      ...options.identity
    },
    isLocal: false,
    cleanup: async () => {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  };
}

export function isSafeTarPath(entryPath: string): boolean {
  if (path.isAbsolute(entryPath)) {
    return false;
  }

  const normalized = path.posix.normalize(entryPath.replaceAll("\\", "/"));
  if (normalized === "." || normalized.startsWith("../") || normalized.includes("/../")) {
    return false;
  }

  return true;
}
