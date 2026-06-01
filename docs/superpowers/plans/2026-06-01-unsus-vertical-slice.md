# unsus Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a clean local TypeScript monorepo for the initial `unsus` package firewall vertical slice.

**Architecture:** `@unsus/core` owns safe resolution, extraction, analyzers, scoring, diffs, and reports. `@unsus/sandbox` owns Docker command construction and sanitized timeline output. `@unsus/cli` parses command arguments and never invokes package managers before a scan decision.

**Tech Stack:** TypeScript, Node.js, npm workspaces, Node test runner, `acorn`, `semver`, and `tar`.

---

### Task 1: Repository Setup

- [x] Initialize clean Git repository.
- [x] Add workspace package files, strict TypeScript config, README, docs, CI, and `.gitignore`.
- [ ] Run typecheck/test.
- [ ] Commit `chore: initialize unsus repo structure`.

### Task 2: Core Types

- [ ] Add shared security report, package, sandbox, diff, and policy types.
- [ ] Run typecheck/test.
- [ ] Commit `feat: add core package types`.

### Task 3: Safe Local and Npm Extraction

- [ ] Add failing tests for local fixture extraction.
- [ ] Implement local extraction and safe file collection.
- [ ] Add safe npm packument/tarball resolver and extractor.
- [ ] Run typecheck/test.
- [ ] Commit `feat: add npm package resolver and safe tarball extraction`.

### Task 4: Static Analyzers and Scoring

- [ ] Add failing tests for metadata, AST, entropy, IOC, binary, and scoring chains.
- [ ] Implement pure analyzers and risk policy functions.
- [ ] Run typecheck/test.
- [ ] Commit analyzer and scoring milestones.

### Task 5: Diff, Sandbox, CLI, Fixtures, Docs

- [ ] Add version diff engine and tests.
- [ ] Add Docker sandbox command scaffolding.
- [ ] Add CLI commands for scan, diff, install, and explain.
- [ ] Add benign and suspicious fixtures.
- [ ] Run final verification.
- [ ] Commit remaining milestones and summarize limitations.
