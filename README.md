# unsus

Install dependencies like they're guilty until proven boring.

`unsus` is a local package firewall for developers, CI, and AI coding agents. It pre-checks npm packages before real package manager installs can run dependency lifecycle scripts on the host machine.

## Safety Model

- Unknown package install scripts are never executed on the host by `unsus`.
- Registry packages are fetched as metadata and tarballs, then extracted without running lifecycle scripts.
- Dynamic checks are opt-in for scans and must run in a Docker sandbox with no network and a sanitized environment.
- Automated tests use harmless synthetic fixtures only. Real malicious package benchmarking is a manual GCloud workflow with explicit opt-in.
- `unsus install` scans before delegating to `npm`, `bun`, or `pnpm`.

## Current Status

This repository is a clean production-quality rewrite. The current vertical slice supports local and npm package scanning, safe npm tarball extraction, static behavioral analyzers, risk scoring, version diffs, a basic install firewall, dynamic Docker sandboxing for local package scans, and a disposable GCloud workflow for remote npm/package-malware benchmarking.

Real-world sample sourcing is handled by research scripts, not core product code. They can build candidate manifests from advisory/dataset metadata, check live npm availability without downloading tarballs, and feed reviewed package specs to the disposable VM runner.

## Commands

```bash
unsus scan <target> [--json] [--dynamic] [--no-dynamic] [--fail-on high]
unsus diff <pkg>@<newVersion> --against <pkg>@<oldVersion> [--json]
unsus install <package> [--pm npm|bun|pnpm] [--force] [--json]
unsus explain <report.json>
```

## Development

Install known development dependencies without lifecycle scripts:

```bash
npm install --ignore-scripts
npm run typecheck
npm test
npm run benchmark:synthetic
```

Local smoke examples:

```bash
node packages/cli/dist/index.js scan fixtures/benign/normal-package --json
node packages/cli/dist/index.js scan fixtures/suspicious/postinstall-env-network --dynamic
node packages/cli/dist/index.js diff fixtures/suspicious/postinstall-env-network --against fixtures/benign/normal-package
```

Real-world sample metadata workflow:

```bash
npm run samples:datadog-npm -- --output artifacts/malware-lab/datadog/npm-candidates.json --limit 200
npm run samples:check-npm -- --input artifacts/malware-lab/datadog/npm-candidates.json --output artifacts/malware-lab/datadog/npm-available.json --json
```

Those commands are metadata-only. They do not download npm tarballs or execute package code.

## Dependency Note

The initial dependency set is intentionally small and mature:

- `typescript` and `@types/node` for strict TypeScript builds.
- `acorn` for JavaScript syntax parsing without executing code.
- `semver` for npm version/range selection.
- `tar` for safe tarball extraction without lifecycle execution.

## What It Detects

- Install-time lifecycle scripts.
- Suspicious shell fragments inside lifecycle scripts.
- Dynamic code execution such as `eval` and `Function`.
- Child process, network, credential, and filesystem access patterns.
- Obfuscation signals and high-entropy strings.
- Binary payloads and executable file extensions.
- Version-to-version additions of risky files, scripts, and dependencies.

## What It Does Not Detect Yet

- Full malware reverse engineering.
- Native sandbox escape attempts.
- Complete source-vs-registry provenance verification.
- Syscall-level network-attempt tracing inside the sandbox.
- Ecosystems outside npm-compatible packages.
- Enterprise fleet inventory.

## False Positive Philosophy

One isolated signal should usually explain and warn. Blocking is reserved for behavioral chains, especially install-time execution combined with credential access, network access, child process execution, obfuscation, or binary payloads.

## Safety Warning

Do not use real suspicious packages for local development. If a test requires real hostile behavior, use the manifest-driven disposable GCloud workflow in `docs/malicious-payload-testing.md`; package tarballs should be fetched on the VM, not on the host.
