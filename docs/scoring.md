# Scoring

`unsus` scores packages by behavior chains rather than isolated findings.

## Defaults

- `safe` and `low`: allow
- `medium`: warn
- `high` and `critical`: block

## Behavior Chains

- install script plus network access: high
- install script plus child process: high
- install script plus sensitive env access plus network: critical
- obfuscation plus dynamic code execution: high
- obfuscation plus child process or network: critical
- credential file reads plus network: critical
- new dependency with install script in a version diff: high
- package name typo plus install script: high
- binary payload plus install script: critical

Provenance absence alone is low/info by default because missing metadata is common and not enough to prove malicious behavior.
