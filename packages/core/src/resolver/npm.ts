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

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-npm-"));
  const tarballPath = path.join(tempDir, "package.tgz");
  const response = await fetchImpl(metadata.dist.tarball);

  if (!response.ok) {
    throw new Error(`Failed to download tarball ${metadata.dist.tarball}: HTTP ${response.status}.`);
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  await fs.writeFile(tarballPath, bytes);

  const extracted = await extractTarballPackage(tarballPath, {
    identity: identityFromMetadata(metadata, request, registry)
  });
  const originalCleanup = extracted.cleanup;

  return {
    ...extracted,
    isLocal: false,
    cleanup: async () => {
      await originalCleanup?.();
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  };
}

export async function fetchPackument(
  name: string,
  registry: string,
  fetchImpl: typeof fetch
): Promise<Packument> {
  const response = await fetchImpl(npmPackumentUrl(name, registry), {
    headers: {
      accept: "application/vnd.npm.install-v1+json, application/json"
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch npm metadata for ${name}: HTTP ${response.status}.`);
  }

  return (await response.json()) as Packument;
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
