# Architecture

`unsus` is organized as an npm workspace with three packages.

- `@unsus/core` resolves, extracts, analyzes, scores, diffs, and reports on packages without executing package code.
- `@unsus/sandbox` owns Docker-based dynamic analysis and timeline capture.
- `@unsus/cli` provides the `unsus` command surface and delegates safety decisions to core.

The core package is intentionally usable from Node-compatible runtimes. Bun can be used for developer speed, but runtime logic avoids Bun-specific APIs.
