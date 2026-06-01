#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";

const args = parseArgs(process.argv.slice(2));
const inputPath = args.input;
const outputPath = args.output;
const registry = (args.registry ?? "https://registry.npmjs.org").replace(/\/+$/, "");

if (!inputPath) {
  console.error("Usage: check-npm-sample-availability.mjs --input candidates.json [--output manifest.json] [--json]");
  process.exit(2);
}

const input = JSON.parse(await readFile(inputPath, "utf8"));
const candidates = normalizeCandidates(input);
const available = [];
const unavailable = [];

for (const candidate of candidates) {
  const parsed = parsePackageSpec(candidate.package);
  if (!parsed) {
    unavailable.push({ ...candidate, reason: "invalid_package_spec" });
    continue;
  }

  if (parsed.requested === "latest") {
    unavailable.push({ ...candidate, reason: "exact_version_required" });
    continue;
  }

  const packumentUrl = npmPackumentUrl(parsed.name, registry);
  let packument;
  try {
    const response = await fetch(packumentUrl, {
      headers: {
        accept: "application/vnd.npm.install-v1+json, application/json"
      }
    });

    if (!response.ok) {
      unavailable.push({ ...candidate, reason: `metadata_http_${response.status}` });
      continue;
    }

    packument = await response.json();
  } catch (error) {
    unavailable.push({ ...candidate, reason: "metadata_fetch_failed", error: errorMessage(error) });
    continue;
  }

  const version = packument?.versions?.[parsed.requested];
  if (!version) {
    unavailable.push({ ...candidate, reason: "version_not_in_packument" });
    continue;
  }

  available.push({
    id: candidate.id,
    package: `${parsed.name}@${parsed.requested}`,
    source: candidate.source,
    notes: candidate.notes ?? "Reviewed real-world npm malware candidate.",
    metadata: {
      registry,
      packageName: parsed.name,
      version: parsed.requested,
      hasTarballUrl: typeof version.dist?.tarball === "string"
    }
  });
}

const result = {
  kind: "unsus-npm-sample-availability-report",
  generatedAt: new Date().toISOString(),
  safety: {
    metadataOnly: true,
    tarballsDownloaded: false,
    lifecycleScriptsExecuted: false
  },
  summary: {
    total: candidates.length,
    available: available.length,
    unavailable: unavailable.length
  },
  available,
  unavailable
};

if (outputPath) {
  const manifest = {
    kind: "unsus-malicious-npm-sample-manifest",
    generatedFrom: inputPath,
    generatedAt: result.generatedAt,
    samples: available.map(({ id, package: packageSpec, source, notes }) => ({
      id,
      package: packageSpec,
      source,
      notes
    }))
  };
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
}

if (args.json || !outputPath) {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} else {
  process.stdout.write(`Available: ${available.length}/${candidates.length}\n`);
  process.stdout.write(`Wrote VM manifest: ${outputPath}\n`);
}

process.exit(unavailable.length > 0 ? 1 : 0);

function normalizeCandidates(input) {
  if (input.kind === "unsus-malicious-npm-sample-manifest" && Array.isArray(input.samples)) {
    return input.samples;
  }

  if (input.kind === "unsus-real-world-npm-candidate-list" && Array.isArray(input.candidates)) {
    return input.candidates;
  }

  if (Array.isArray(input)) {
    return input;
  }

  throw new Error("Expected a candidate list or existing malicious sample manifest.");
}

function parsePackageSpec(spec) {
  if (typeof spec !== "string" || !isNpmPackageRequest(spec)) {
    return undefined;
  }

  if (spec.startsWith("@")) {
    const at = spec.indexOf("@", 1);
    return at === -1
      ? { name: spec, requested: "latest" }
      : { name: spec.slice(0, at), requested: spec.slice(at + 1) || "latest" };
  }

  const at = spec.lastIndexOf("@");
  return at <= 0
    ? { name: spec, requested: "latest" }
    : { name: spec.slice(0, at), requested: spec.slice(at + 1) || "latest" };
}

function isNpmPackageRequest(spec) {
  const trimmed = spec.trim();
  if (!trimmed || trimmed.startsWith(".") || trimmed.startsWith("/") || trimmed.includes("\\")) {
    return false;
  }

  if (trimmed.startsWith("@")) {
    return /^@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(@[A-Za-z0-9._~+^-]+)?$/.test(trimmed);
  }

  return !trimmed.includes("/") && /^[A-Za-z0-9._-]+(@[A-Za-z0-9._~+^-]+)?$/.test(trimmed);
}

function npmPackumentUrl(name, npmRegistry) {
  const encodedName = name.startsWith("@") ? name.replace("/", "%2f") : encodeURIComponent(name);
  return `${npmRegistry}/${encodedName}`;
}

function parseArgs(rawArgs) {
  const parsed = {};
  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    if (arg === "--json") {
      parsed.json = true;
      continue;
    }

    if (arg === "--input" || arg === "--output" || arg === "--registry") {
      parsed[arg.slice(2)] = rawArgs[index + 1];
      index += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
