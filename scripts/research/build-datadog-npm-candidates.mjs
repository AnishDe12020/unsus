#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";

const DEFAULT_MANIFEST_URL =
  "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json";
const DATASET_SOURCE = "DataDog/malicious-software-packages-dataset";

const args = parseArgs(process.argv.slice(2));
const input = args.input ?? DEFAULT_MANIFEST_URL;
const output = args.output;
const limit = args.limit ? Number.parseInt(args.limit, 10) : undefined;
const offset = args.offset ? Number.parseInt(args.offset, 10) : 0;

if (limit !== undefined && (!Number.isInteger(limit) || limit <= 0)) {
  throw new Error("--limit must be a positive integer.");
}

if (!Number.isInteger(offset) || offset < 0) {
  throw new Error("--offset must be a non-negative integer.");
}

const manifest = await loadManifest(input);
const packageEntries = Object.entries(manifest).sort(([left], [right]) => left.localeCompare(right));
const candidates = [];
const unversioned = [];
const malformed = [];

for (const [name, versions] of packageEntries) {
  if (!isValidPackageName(name)) {
    malformed.push({ name, reason: "invalid_package_name" });
    continue;
  }

  if (versions === null) {
    unversioned.push({
      name,
      reason: "datadog_manifest_marks_all_versions_malicious"
    });
    continue;
  }

  if (!Array.isArray(versions)) {
    malformed.push({ name, reason: "version_entry_not_null_or_array" });
    continue;
  }

  for (const version of versions) {
    if (typeof version !== "string" || !isValidVersionToken(version)) {
      malformed.push({ name, version, reason: "invalid_version" });
      continue;
    }

    candidates.push({
      id: candidateId(name, version),
      package: `${name}@${version}`,
      source: `${DATASET_SOURCE}: samples/npm/manifest.json`,
      notes:
        "DataDog malicious software packages dataset marks this exact npm package version as malicious. Metadata only; package artifact not downloaded by this script."
    });
  }
}

const selectedCandidates = candidates.slice(offset, limit ? offset + limit : undefined);
const report = {
  kind: "unsus-datadog-npm-candidate-report",
  generatedAt: new Date().toISOString(),
  input,
  safety: {
    metadataOnly: true,
    sampleArchivesExtracted: false,
    packageTarballsDownloaded: false,
    lifecycleScriptsExecuted: false
  },
  summary: {
    totalPackages: packageEntries.length,
    exactCandidates: candidates.length,
    offset,
    emittedCandidates: selectedCandidates.length,
    unversionedPackages: unversioned.length,
    malformedEntries: malformed.length
  },
  unversionedPreview: unversioned.slice(0, 50),
  unversionedOmitted: Math.max(0, unversioned.length - 50),
  malformedPreview: malformed.slice(0, 50),
  malformedOmitted: Math.max(0, malformed.length - 50)
};

if (output) {
  const candidateList = {
    kind: "unsus-real-world-npm-candidate-list",
    generatedAt: report.generatedAt,
    generatedFrom: input,
    source: DATASET_SOURCE,
    safety: report.safety,
    candidates: selectedCandidates
  };

  await writeFile(output, `${JSON.stringify(candidateList, null, 2)}\n`, { flag: args.force ? "w" : "wx" });
}

if (args.json || !output) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} else {
  process.stdout.write(`Exact candidates: ${selectedCandidates.length}/${candidates.length}\n`);
  process.stdout.write(`Unversioned packages skipped: ${unversioned.length}\n`);
  process.stdout.write(`Wrote candidate list: ${output}\n`);
}

function parseArgs(rawArgs) {
  const parsed = {};

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    if (arg === "--json" || arg === "--force") {
      parsed[arg.slice(2)] = true;
      continue;
    }

    if (arg === "--input" || arg === "--output" || arg === "--limit" || arg === "--offset") {
      parsed[arg.slice(2)] = rawArgs[index + 1];
      index += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
}

async function loadManifest(input) {
  const text = input.startsWith("https://") ? await fetchText(input) : await readFile(input, "utf8");
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("DataDog npm manifest must be a JSON object.");
  }
  return parsed;
}

async function fetchText(url) {
  const response = await fetch(url, {
    headers: {
      accept: "application/json,text/plain"
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch DataDog npm manifest: HTTP ${response.status}.`);
  }

  return response.text();
}

function isValidPackageName(name) {
  if (typeof name !== "string" || name.trim() !== name || name.length === 0) {
    return false;
  }

  if (name.startsWith("@")) {
    return /^@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(name);
  }

  return /^[A-Za-z0-9._-]+$/.test(name);
}

function isValidVersionToken(version) {
  return /^[A-Za-z0-9._~+^-]+$/.test(version);
}

function candidateId(name, version) {
  return `datadog-${name}@${version}`
    .toLowerCase()
    .replace(/^@/, "")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
