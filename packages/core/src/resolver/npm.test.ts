import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import * as tar from "tar";
import { resolveNpmPackage, type NpmResolverOptions } from "./npm.js";

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "unsus-test-npm-"));
  await mkdir(path.join(root, "package"));
  await writeFile(path.join(root, "package/package.json"), JSON.stringify({ name: "synthetic-example", version: "1.0.0" }));
  await writeFile(path.join(root, "package/index.js"), "export const answer = 42;");
  await tar.c({ gzip: true, file: path.join(root, "package.tgz"), cwd: root }, ["package"]);
  const bytes = await readFile(path.join(root, "package.tgz"));
  const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  const resolve = (overrides: Record<string, unknown> = {}, served = bytes, options = {}) => resolveNpmPackage("synthetic-example", {
    ...options,
    fetchImpl: async (url) => String(url).endsWith("fixture.tgz")
      ? new Response(served)
      : Response.json({ name: "synthetic-example", "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name: "synthetic-example", version: "1.0.0", dist: { tarball: "https://registry.npmjs.org/fixture.tgz", integrity }, ...overrides } } })
  } as NpmResolverOptions);
  return { root, bytes, integrity, resolve };
}

test("registry resolver verifies bytes and retains the exact archive until cleanup", async () => {
  const f = await fixture();
  try {
    const pkg = await f.resolve();
    try {
      assert.equal(pkg.identity.integrity, f.integrity);
      assert.ok("tarballPath" in pkg && typeof pkg.tarballPath === "string");
      assert.deepEqual(await readFile(pkg.tarballPath), f.bytes);
    } finally { await pkg.cleanup?.(); }
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("registry resolver rejects tampered bytes and cleans temporary downloads", async () => {
  const f = await fixture();
  const before = new Set(await readdir(os.tmpdir()));
  try {
    await assert.rejects(f.resolve({}, Buffer.from("tampered")), /integrity/i);
    const leaked = (await readdir(os.tmpdir())).filter((name) => name.startsWith("unsus-npm-") && !before.has(name));
    assert.deepEqual(leaked, []);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("registry resolver rejects missing checksums, metadata mismatch and oversized downloads", async () => {
  const f = await fixture();
  try {
    await assert.rejects(f.resolve({ dist: { tarball: "https://registry.npmjs.org/fixture.tgz" } }), /integrity|checksum/i);
    await assert.rejects(f.resolve({ name: "different-package" }), /identity|match/i);
    await assert.rejects(f.resolve({}, f.bytes, { maxDownloadBytes: 16 }), /limit|large/i);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("resolver rejects insecure and credential-bearing metadata URLs before fetching", async () => {
  for (const registry of ["http://registry.example", "ftp://registry.example", "https://user:password@registry.example"]) {
    let fetched = false;
    await assert.rejects(resolveNpmPackage("synthetic-example", { registry, fetchImpl: async () => { fetched = true; return Response.json({}); } }), /HTTPS|credentials|transport/i);
    assert.equal(fetched, false);
  }
});

test("metadata final response cannot downgrade to insecure transport", async () => {
  await assert.rejects(resolveNpmPackage("synthetic-example", { fetchImpl: async () => {
    const response = Response.json({});
    Object.defineProperty(response, "url", { value: "http://registry.example/synthetic-example" });
    return response;
  } }), /HTTPS|transport/i);
});
