# Architecture

`unsus` is organized as an npm workspace with three packages.

- `@unsus/core` resolves, extracts, analyzes, scores, diffs, and reports on packages without executing package code.
- `@unsus/sandbox` owns Docker-based dynamic analysis and timeline capture.
- `@unsus/cli` provides the `unsus` command surface and delegates safety decisions to core.

The core package is intentionally usable from Node-compatible runtimes. Bun can be used for developer speed, but runtime logic avoids Bun-specific APIs.

## Current Flow

1. CLI resolves a local path or npm package request.
2. Core fetches package metadata/tarballs without executing lifecycle scripts.
3. Core extracts into a temporary directory and collects bounded file contents.
4. Pure analyzers emit behavioral findings.
5. Scoring converts behavior chains into allow, warn, or block decisions.
6. If `--dynamic` is enabled and a sandbox runner is configured, lifecycle scripts execute only inside a hardened Docker container and produce a timeline.
7. `unsus install` delegates to the selected package manager only after the scan decision permits it or the user forces an override.

## Research Scripts

Research helpers under `scripts/research/` are intentionally outside the core product packages. They support real-world test sourcing by:

- building npm candidate lists from the DataDog malicious package dataset manifest;
- checking live npm metadata availability without downloading tarballs;
- producing ignored manifests for the disposable GCloud runner.

They must not extract malicious sample archives, fetch npm tarballs locally, or execute package code.
