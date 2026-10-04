import { createHash, timingSafeEqual } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import semver from "semver";

import type { ExtractedPackage, PackageIdentity } from "../types.js";
import { extractTarballPackage } from "../extract/tarball.js";
import { npmPackumentUrl, parsePackageRequest } from "./package-manager.js";

export interface NpmResolverOptions {
  registry?: string;
  fetchImpl?: typeof fetch;
  maxDownloadBytes?: number;
}

interface PackumentVersion {
  name: string;
  version: string;
  dist?: {
    tarball?: string;
    integrity?: string;
    shasum?: string;
  };
  repository?: unknown;
}

interface Packument {
  name: string;
  versions: Record<string, PackumentVersion>;
  "dist-tags"?: Record<string, string>;
}

export async function resolveNpmPackage(
  request: string,
  options: NpmResolverOptions = {}
): Promise<ExtractedPackage> {
  const packageRequest = parsePackageRequest(request);
  const fetchImpl = options.fetchImpl ?? fetch;
  const registry = options.registry ?? "https://registry.npmjs.org";
  const packument = await fetchPackument(packageRequest.name, registry, fetchImpl);
  const version = resolveVersion(packument, packageRequest.requested);
  const metadata = packument.versions[version];

  if (!metadata?.dist?.tarball) {
    throw new Error(`No tarball URL found for ${packageRequest.name}@${version}.`);
  }

  if (metadata.name !== packageRequest.name || metadata.version !== version) {
    throw new Error("Registry metadata identity does not match the requested package.");
  }
  const url = new URL(metadata.dist.tarball);
  const registryUrl = new URL(registry);
  if (url.protocol !== "https:" && !(url.origin === registryUrl.origin && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) {
    throw new Error("Package tarball requires HTTPS (or an explicitly configured loopback registry).");
  }
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-npm-"));
  const tarballPath = path.join(tempDir, "package.tgz");
  let extracted: ExtractedPackage | undefined;
  try {
    const response = await fetchImpl(url.href, { signal: AbortSignal.timeout(30_000), redirect: "error" });
    if (!response.ok) throw new Error(`Failed to download tarball: HTTP ${response.status}.`);
    const bytes = await readBoundedResponse(response, options.maxDownloadBytes ?? 20 * 1024 * 1024);
    const integrity = verifyIntegrity(bytes, metadata.dist.integrity, metadata.dist.shasum);
    await fs.writeFile(tarballPath, bytes, { mode: 0o600 });
    extracted = await extractTarballPackage(tarballPath);
    if (extracted.identity.name !== packageRequest.name || extracted.identity.version !== version) {
      throw new Error("Tarball package identity does not match registry metadata.");
    }
    const originalCleanup = extracted.cleanup;
    return {
      ...extracted,
      identity: { ...identityFromMetadata(metadata, request, registry), integrity },
      tarballPath,
      isLocal: false,
      cleanup: async () => {
        try { await originalCleanup?.(); }
        finally { await fs.rm(tempDir, { recursive: true, force: true }); }
      }
    };
  } catch (error) {
    try { await extracted?.cleanup?.(); }
    finally { await fs.rm(tempDir, { recursive: true, force: true }); }
    throw error;
  }
}

export async function fetchPackument(
  name: string,
  registry: string,
  fetchImpl: typeof fetch
): Promise<Packument> {
  const response = await fetchImpl(npmPackumentUrl(name, registry), {
    signal: AbortSignal.timeout(30_000),
    redirect: "error",
    headers: {
      accept: "application/vnd.npm.install-v1+json, application/json"
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch npm metadata for ${name}: HTTP ${response.status}.`);
  }

  return JSON.parse((await readBoundedResponse(response, 20 * 1024 * 1024)).toString("utf8")) as Packument;
}

export function resolveVersion(packument: Packument, requested: string): string {
  const versions = Object.keys(packument.versions);

  if (requested === "latest") {
    const latest = packument["dist-tags"]?.latest;
    if (latest && packument.versions[latest]) {
      return latest;
    }
  }

  if (packument.versions[requested]) {
    return requested;
  }

  const resolved = semver.maxSatisfying(versions, requested);
  if (resolved) {
    return resolved;
  }

  throw new Error(`Could not resolve ${packument.name}@${requested}.`);
}

function identityFromMetadata(
  metadata: PackumentVersion,
  requested: string,
  registry: string
): PackageIdentity {
  const repositoryUrl =
    typeof metadata.repository === "object" &&
    metadata.repository !== null &&
    "url" in metadata.repository &&
    typeof metadata.repository.url === "string"
      ? metadata.repository.url
      : undefined;

  return {
    name: metadata.name,
    version: metadata.version,
    requested,
    registry,
    ...(metadata.dist?.tarball ? { tarballUrl: metadata.dist.tarball } : {}),
    ...(metadata.dist?.integrity ?? metadata.dist?.shasum
      ? { integrity: metadata.dist?.integrity ?? metadata.dist?.shasum }
      : {}),
    ...(repositoryUrl ? { repositoryUrl } : {})
  };
}

async function readBoundedResponse(response: Response, limit: number): Promise<Buffer> {
  const declared = Number(response.headers.get("content-length"));
  if (declared > limit) { await response.body?.cancel(); throw new Error("Download exceeds byte limit."); }
  if (!response.body) throw new Error("Download body is missing.");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error("Download exceeds byte limit.");
      chunks.push(value);
    }
  } catch (error) { await reader.cancel(); throw error; }
  finally { reader.releaseLock(); }
  return Buffer.concat(chunks, size);
}

function verifyIntegrity(bytes: Buffer, integrity?: string, shasum?: string): string {
  // Use the strongest supported SRI algorithm. Never downgrade a failed strong hash.
  if (integrity) {
    const tokens = integrity.trim().split(/\s+/);
    for (const algorithm of ["sha512", "sha384", "sha256", "sha1"]) {
      const candidates = tokens.filter((token) => token.startsWith(`${algorithm}-`));
      if (!candidates.length) continue;
      const digest = createHash(algorithm).update(bytes).digest();
      if (candidates.some((token) => {
        const encoded = token.slice(algorithm.length + 1);
        const expected = Buffer.from(encoded, "base64");
        return expected.toString("base64") === encoded && expected.length === digest.length && timingSafeEqual(expected, digest);
      })) return `${algorithm}-${digest.toString("base64")}`;
      throw new Error("Package integrity verification failed.");
    }
    throw new Error("Unsupported package integrity checksum.");
  }
  if (shasum && /^[a-f0-9]{40}$/i.test(shasum) && createHash("sha1").update(bytes).digest("hex") === shasum.toLowerCase()) {
    return `sha1-${Buffer.from(shasum, "hex").toString("base64")}`;
  }
  throw new Error("Package integrity checksum missing or invalid.");
}
