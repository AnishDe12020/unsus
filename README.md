# unsus

Install dependencies like they're guilty until proven boring.

`unsus` is a local package firewall for developers, CI, and AI coding agents. It pre-checks npm packages before real package manager installs can run dependency lifecycle scripts on the host machine.

## Safety Model

- Unknown package install scripts are never executed on the host by `unsus`.
- Registry packages are fetched as metadata and tarballs, then extracted without running lifecycle scripts.
- Dynamic checks are opt-in for scans and must run in a Docker sandbox with no network and a sanitized environment.
- Tests use harmless synthetic fixtures only. No real malware samples are used.
- `unsus install` scans before delegating to `npm`, `bun`, or `pnpm`.

## Current Status

This repository is a clean production-quality rewrite. The first vertical slice supports local fixture scanning, safe npm tarball extraction, static behavioral analyzers, risk scoring, version diffs, hardened Docker command construction, and a basic CLI.

Dynamic lifecycle execution is not wired into `scan` or `install` yet. The sandbox package currently builds the hardened Docker invocation shape; the next step is executing package lifecycle scripts inside that sandbox and returning a timeline.

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
```

Local smoke examples:

```bash
node packages/cli/dist/index.js scan fixtures/benign/normal-package --json
node packages/cli/dist/index.js diff fixtures/suspicious/postinstall-env-network --against fixtures/benign/normal-package
```

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
- Ecosystems outside npm-compatible packages.
- Enterprise fleet inventory.

## False Positive Philosophy

One isolated signal should usually explain and warn. Blocking is reserved for behavioral chains, especially install-time execution combined with credential access, network access, child process execution, obfuscation, or binary payloads.

## Safety Warning

Do not use real suspicious packages for local development. If a test requires real hostile behavior, run it only in an isolated cloud VM or no-network container after an explicit safety plan.
