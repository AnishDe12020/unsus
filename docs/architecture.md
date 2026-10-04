# Architecture

`unsus` is an npm workspace with three packages, targeting Node.js 22 or newer.

- `@unsus/core` resolves, extracts, analyzes, scores, diffs, and reports on direct packages without executing their code.
- `@unsus/sandbox` provides optional Docker lifecycle-script observation.
- `@unsus/cli` provides scan, diff, offline project inspection, guarded npm install, and saved-report rendering.

## Scan and install flow

1. A scan resolves a local directory or registry request. The installer accepts only a registry package request.
2. Registry resolution fetches metadata and archive bytes over HTTPS, verifies integrity and identity, and extracts with path, entry, and inflation limits.
3. Static heuristics inspect bounded file contents and lifecycle metadata. Omitted text files make the scan require review. Dependencies are not analyzed.
4. Findings produce an allow, warn, or block decision. These decisions are heuristic; they cannot establish safety.
5. Explicit dynamic observation runs lifecycle scripts in a copied Docker workspace. Networking is disabled and dependencies are not installed. Requested observation fails if Docker cannot run or teardown cannot be confirmed.
6. A guarded install retains the exact scanned archive under the project's `.unsus/artifacts/` and runs npm against it with `--ignore-scripts`. Warnings require `--yes`; a blocked scan requires `--force`. Neither override enables scripts or bypasses integrity errors.

The archive remains a relative `file:` dependency in the project's manifest and lockfile. Users must retain it. npm resolves transitive dependencies; unsus does not scan those bytes. Later imports, execution, and installs without `--ignore-scripts` are outside this protection.

`project` follows a separate offline path: read a bounded project manifest, select declared direct dependencies, and inspect matching regular directories under that project's `node_modules`. Linked packages and unsupported specifications are explicit coverage gaps. Package count, entry count and total file sizes are bounded. No resolver, installer, lockfile writer or dynamic runner is invoked. Reports retain per-package findings and coverage; an operational inspection failure takes exit 3 ahead of policy exits, while any gap prevents an aggregate allow. Registry and lockfile integrity are unverified.

## Distribution

`npm run package:release` packs the three compiled workspaces, installs their runtime dependencies at versions pinned by the repository lockfile with scripts disabled, and emits a portable archive plus SHA-256 checksum. The kit includes dependency licenses and the package archives. It needs Node.js, but no build or npm registry publication, to run. Verification exercises the extracted kit from an unrelated directory.

## Research scripts

`docs/` and `scripts/research/` also contain historical sample-sourcing and disposable-lab workflows. They are outside the v0.2 product path. Research helpers build candidate lists and check metadata availability; they must not extract or execute malicious samples on a development machine.
