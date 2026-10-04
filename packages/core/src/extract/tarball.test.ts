import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, writeFile, symlink, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import * as tar from "tar";
import { extractTarballPackage, isSafeTarPath, type ExtractTarballOptions } from "./tarball.js";

test("tar path validation rejects traversal, Windows paths and backslashes", () => {
  for (const unsafe of ["package/../outside", "C:/outside", "package\\file", "/outside", "../outside"]) assert.equal(isSafeTarPath(unsafe), false, unsafe);
  assert.equal(isSafeTarPath("package/dist/index.js"), true);
});

test("extraction rejects symlinks and oversized archive contents", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-test-tar-"));
  try {
    await mkdir(path.join(root, "package"));
    await writeFile(path.join(root, "package/package.json"), '{"name":"fixture","version":"1.0.0"}');
    await symlink("package.json", path.join(root, "package/link"));
    const archive = path.join(root, "package.tgz");
    await tar.c({ gzip: true, file: archive, cwd: root }, ["package"]);
    await assert.rejects(extractTarballPackage(archive), /link|type/i);
    await rm(path.join(root, "package/link"));
    await tar.c({ gzip: true, file: archive, cwd: root }, ["package"]);
    await assert.rejects(extractTarballPackage(archive, { maxExtractedBytes: 8 } as ExtractTarballOptions), /limit|large/i);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("extraction bounds decompressed bytes even when gzip contains no tar entries", async () => {
  const { gzipSync } = await import("node:zlib");
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-test-bomb-"));
  try {
    const archive = path.join(root, "zero.tgz");
    await writeFile(archive, gzipSync(Buffer.alloc(1024 * 1024)));
    await assert.rejects(extractTarballPackage(archive, { maxExtractedBytes: 1024 }), /limit/i);
  } finally { await rm(root, { recursive: true, force: true }); }
});
