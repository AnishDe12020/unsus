# Safe Testing

`unsus` development must avoid executing unknown package code on the host.

## Rules

- Never run suspicious `npm install`, `bun add`, or `pnpm add` commands directly on the host.
- Never execute lifecycle scripts from unknown packages on the host.
- Fetch npm tarballs for analysis only; extraction must not execute package scripts.
- Do not use real malware samples in automated tests or on the host.
- Do not read, print, store, or pass through real host secrets.
- Do not contact suspicious domains or URLs.

## Fixtures

Fixtures are harmless local packages used to test detection logic. Suspicious fixtures may contain code text that would be risky in a real package, but tests must inspect it statically instead of executing it on the host.

Use fake secret names such as `FAKE_TEST_TOKEN` instead of real credential names where executable fixture code might be run accidentally.

## Docker Sandbox

Dynamic analysis must run only inside Docker with:

- `--network=none`
- `--read-only` where practical
- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- memory, CPU, and PID limits
- temporary workspaces only
- no home directory, SSH, npm, GitHub, or cloud config mounts
- sanitized environment variables

Local `scan --dynamic` can execute lifecycle scripts inside Docker and return a sandbox timeline. Registry scans require an additional `--allow-remote-dynamic` opt-in; `install --dynamic` explicitly opts in for its registry package. These switches do not make hostile samples safe. Real malicious-package experiments belong in the separately reviewed disposable GCloud workflow, never routine development or CI.

## When to Use Cloud VMs

Stop and request a cloud VM plan before testing real suspicious packages, unknown malware-like samples, internet-observed hostile payloads, or anything that requires networked dynamic analysis.

The current VM path is documented in:

- `docs/gcloud-sandbox.md`
- `docs/malicious-payload-testing.md`
- `docs/real-world-sample-sourcing.md`
