# Scoring

`unsus` combines weighted heuristic findings with score floors for selected combinations. These combinations describe signals found across a package, not proven data flow or proof that a lifecycle script reaches particular code.

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
- binary payload plus install script: critical

Low-signal URLs and entropy findings are capped when no stronger combination applies. Isolated capabilities also require review rather than automatically blocking. Dense source obfuscation can independently reach a blocking score. Incomplete text coverage forces at least a review decision even when the numeric score is low.

Version diffs use finding severity directly for their exit status: new or changed lifecycle hooks and dangerous file findings block; new dependencies require review. Diffing does not resolve new dependencies or inspect their scripts. Typosquat and provenance detection are not implemented as complete detectors in this release.
