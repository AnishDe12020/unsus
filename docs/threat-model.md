# Threat model

The v0.2 product inspects a direct npm package before installation and keeps lifecycle scripts disabled during a guarded npm install. It aims to expose suspicious package behavior for review; it does not certify packages or provide complete host protection.

## What it handles

- Registry archive tampering relative to advertised integrity, inconsistent identities, unsafe paths and archive entries, and oversized downloads/extraction.
- Heuristic signals in direct-package lifecycle metadata and bounded source files, including credential access, execution, network APIs, and obfuscation.
- Installation of the exact archive inspected, with npm's `--ignore-scripts` applied to project, direct, and transitive lifecycle scripts during that invocation.
- Optional lifecycle observation in a Docker container with networking disabled, constrained resources, dropped capabilities, a read-only root, and no host credentials supplied by unsus.

A checksum proves agreement with registry metadata, not maintainer trust. A compromised registry account can publish malicious bytes with a valid checksum. Static signals may miss behavior or flag legitimate code; the scanner does not perform complete semantic or data-flow analysis. Large text files and unsupported formats have limited coverage.

## Outside this release's coverage

- Scanning or verifying the complete transitive dependency graph, including bundled dependencies.
- Protection when installed code is imported or executed later, or when subsequent installs enable lifecycle scripts.
- Complete typosquat detection, vulnerability databases, provenance verification, or comparison against a trusted source repository.
- Full malware reverse engineering, syscall tracing, network-attempt detection, or sandbox-escape detection.
- Private registry authentication, redirecting registries, other package managers, and non-npm ecosystems.

Docker observation is experimental and is not a proven boundary for hostile samples. It runs no dependency installation, so missing dependencies may prevent useful observation. Development and CI use harmless synthetic fixtures; historical real-sample research belongs in a separately reviewed disposable lab.
