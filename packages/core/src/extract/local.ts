import { promises as fs } from "node:fs";
import path from "node:path";

import type { ExtractedPackage, PackageFile, PackageIdentity } from "../types.js";

const DEFAULT_MAX_TEXT_BYTES = 256 * 1024;
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "coverage"]);
const SOURCE_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".mts",
  ".cts"
]);
const TEXT_EXTENSIONS = new Set([
  ".md",
  ".txt",
  ".yml",
  ".yaml",
  ".toml",
  ".lock",
  ".sh",
  ".ps1",
  ".bat",
  ".cmd"
]);

export interface CollectFilesOptions {
  maxTextBytes?: number;
}

export async function extractLocalPackage(
  rootPath: string,
  options: CollectFilesOptions = {}
): Promise<ExtractedPackage> {
  const resolvedRoot = path.resolve(rootPath);
  const packageJsonPath = path.join(resolvedRoot, "package.json");
  const packageJson = JSON.parse(await fs.readFile(packageJsonPath, "utf8")) as Record<string, unknown>;
  const identity = identityFromPackageJson(packageJson);
  const files = await collectPackageFiles(resolvedRoot, options);

  return {
    identity,
    rootPath: resolvedRoot,
    files,
    packageJson,
    isLocal: true
  };
}

export async function collectPackageFiles(
  rootPath: string,
  options: CollectFilesOptions = {}
): Promise<PackageFile[]> {
  const maxTextBytes = options.maxTextBytes ?? DEFAULT_MAX_TEXT_BYTES;
  const files: PackageFile[] = [];

  async function walk(directory: string): Promise<void> {
    const entries = await fs.readdir(directory, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) {
        continue;
      }

      const absolutePath = path.join(directory, entry.name);
      const relativePath = toPackagePath(path.relative(rootPath, absolutePath));

      if (entry.isDirectory()) {
        await walk(absolutePath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const stat = await fs.stat(absolutePath);
      const kind = classifyFile(relativePath);
      const headerBytes = await readHeader(absolutePath);
      const packageFile: PackageFile = {
        path: relativePath,
        size: stat.size,
        kind,
        headerBytes
      };

      if (shouldReadContent(kind, stat.size, maxTextBytes, headerBytes)) {
        packageFile.content = await fs.readFile(absolutePath, "utf8");
      }

      files.push(packageFile);
    }
  }

  await walk(rootPath);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

export function classifyFile(filePath: string): PackageFile["kind"] {
  const lowerPath = filePath.toLowerCase();
  const extension = path.extname(lowerPath);

  if (lowerPath.endsWith("package.json") || extension === ".json") {
    return "json";
  }

  if (SOURCE_EXTENSIONS.has(extension)) {
    return "source";
  }

  if (TEXT_EXTENSIONS.has(extension)) {
    return "text";
  }

  if (isBinaryExtension(extension)) {
    return "binary";
  }

  return "other";
}

export function identityFromPackageJson(packageJson: Record<string, unknown>): PackageIdentity {
  const name = typeof packageJson.name === "string" ? packageJson.name : "(anonymous)";
  const version = typeof packageJson.version === "string" ? packageJson.version : "0.0.0";

  return { name, version };
}

function shouldReadContent(
  kind: PackageFile["kind"],
  size: number,
  maxTextBytes: number,
  headerBytes: Uint8Array
): boolean {
  if (!(kind === "source" || kind === "json" || kind === "text")) {
    return false;
  }

  if (size > maxTextBytes) {
    return false;
  }

  return !headerBytes.includes(0);
}

function isBinaryExtension(extension: string): boolean {
  return [".exe", ".dll", ".so", ".dylib", ".node", ".bin"].includes(extension);
}

async function readHeader(filePath: string): Promise<Uint8Array> {
  const handle = await fs.open(filePath, "r");
  try {
    const buffer = Buffer.alloc(16);
    const result = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, result.bytesRead);
  } finally {
    await handle.close();
  }
}

function toPackagePath(value: string): string {
  return value.split(path.sep).join("/");
}
