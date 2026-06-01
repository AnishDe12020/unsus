# Threat Model

## Assets Protected

- Developer machines.
- Environment variables.
- SSH keys.
- npm tokens.
- GitHub tokens.
- Cloud credentials.
- CI secrets.
- Local project source trees.

## Attacker Capabilities

- Compromised maintainer account.
- Malicious new package.
- Typosquat package.
- Registry-only tarball payload that differs from source control.
- Postinstall malware.
- Transitive dependency payload.
- Obfuscated JavaScript that hides execution, credential access, or network behavior.

## Primary Defenses

- Fetch and inspect npm metadata and tarballs without running package code.
- Detect install-time execution and suspicious behavior chains.
- Run dynamic lifecycle checks only in a Docker sandbox with no network, resource limits, dropped capabilities, and sanitized environment.
- Block high-risk installs before the real package manager runs on the host.

## Out of Scope Initially

- Native exploit sandbox escapes.
- Full malware reverse engineering.
- Browser extension scanning.
- PyPI, RubyGems, Cargo, Maven, Go modules, and other ecosystems.
- Enterprise fleet inventory.
- Real-time EDR.
