# unsus

Inspect an npm package before installing it, and keep installation scripts off.

`unsus` is a heuristic scanner and guarded npm installer. The v0.1 release candidate scans a **direct package**, verifies its registry archive, and installs those exact bytes with `npm --ignore-scripts`. It does not certify that a package is safe, scan the dependency graph, or protect you when you later import or execute installed code.

## Download the compiled CLI

Download `unsus-0.1.0.tar.gz` and its `.sha256` file from [GitHub Releases](https://github.com/AnishDe12020/unsus/releases). Requires **Node.js 22+**; the kit includes compiled code and runtime dependencies, so no build or npm package publication is needed.

```sh
shasum -a 256 -c unsus-0.1.0.tar.gz.sha256
tar -xzf unsus-0.1.0.tar.gz
./unsus-0.1.0/bin/unsus --help
```

On Windows, extract the archive and run `node unsus-0.1.0/bin/unsus --help`. On macOS/Linux, move the whole extracted directory somewhere permanent and add its `bin` directory to `PATH`, or symlink `bin/unsus` into a directory already on `PATH`. Keep the entire kit together. Local static scans work offline; registry scans need network access, guarded installs also need npm, and dynamic observation needs Docker.

## Try it from source

Requires Node.js 22 or newer and npm. Docker is needed only for optional dynamic observation.

```sh
git clone https://github.com/AnishDe12020/unsus.git
cd unsus
npm ci --ignore-scripts
npm run build
node packages/cli/dist/index.js --help
node packages/cli/dist/index.js scan fixtures/benign/normal-package --json
```

The publishable packages are `@unsus/core`, `@unsus/sandbox`, and `@unsus/cli`, version `0.1.0`. npm registry publication is a separate step; the downloadable kit works without it. `npm run package:release` writes a verified archive and SHA-256 file to `artifacts/release/`. `npm run verify:release` exercises the same build in a temporary directory. Both pack all three workspaces, install their locked runtime dependency versions with scripts disabled, then verify the extracted kit. Neither publishes anything.

To use the checkout's CLI in another project, invoke its absolute path:

```sh
cd /path/to/your-project  # must already contain package.json
node /path/to/unsus/packages/cli/dist/index.js install package-name@1.2.3
```

## Commands

```sh
unsus scan <directory-or-registry-package> [--format text|json|sarif] [--output PATH] [--json] [--fail-on high]
unsus scan <directory> --dynamic
unsus scan <registry-package> --dynamic --allow-remote-dynamic
unsus diff <new-target> --against <old-target> [--json]
unsus install <registry-package> [--registry URL] [--dynamic] [--yes] [--force] [--json]
unsus explain <report.json>
unsus --version
unsus <command> --help
```

`scan` and `diff` accept local directories and registry names, exact versions, or supported semver ranges. Scanning never runs package code unless dynamic observation is explicitly requested. The installer supports **npm only**; it rejects local paths, Git URLs, tarball URLs, bun and pnpm with an error. It does not forward arbitrary npm flags.

Exit codes are **0** allowed/completed, **1** warning requiring review, **2** blocked, and **3** operational failure. An `allow` decision means no blocking rule matched. It is not a safety certificate. JSON reports include direct-package coverage and omitted text files. Installer JSON stays on stdout; npm progress and installation guidance go to stderr.

## Reports for CI

Static scans can emit [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html), JSON, or text. With the CLI on `PATH`, run this in the package directory being checked:

```sh
# Create the report outside the scanned directory to avoid scanning old reports.
report_dir="$(mktemp -d)"
status=0
unsus scan . --format sarif --output "$report_dir/unsus.sarif" || status=$?
# Retain this report with your CI system's artifact step; unsus never uploads it.
printf 'Report: %s\n' "$report_dir/unsus.sarif"
exit "$status"
```

Report files are replaced atomically; the parent directory must already exist. A report write failure exits **3**, while a successfully saved report preserves the scan's **0/1/2** policy status. `--output` leaves stdout empty. `--json` remains an alias for `--format json`; conflicting formats are rejected.

SARIF includes rule metadata, severity, valid observed locations, and explicit direct-package coverage. File URIs are relative to the **scanned package**, using `%PACKAGE_ROOT%`; configure that base in your viewer. A registry package's files are not automatically locations in your CI checkout. Line numbers are included only when recorded by the analyzer. `unsus/matchedEvidence/v1` is a partial fingerprint hashing the rule type and matched evidence, independent of line number. It is omitted when evidence or a safe relative location is unavailable.

SARIF excludes source snippets, raw finding messages, environment variables, registry URLs, and absolute machine paths. Use JSON locally when full finding evidence is needed. SARIF is static-only: combine dynamic observation with text or JSON instead. No format expands scan coverage or establishes that a package is safe.

## What a guarded install does

1. Resolves the registry request once and downloads its archive with a timeout and byte limit.
2. Verifies the strongest supported registry integrity checksum (or legacy SHA-1 shasum), checks the package name/version against metadata, and rejects unsafe archive entries. Integrity establishes agreement with the registry, not author trust.
3. Runs static analysis on the extracted direct package. Warnings require `--yes`; blocked findings require `--force` after review. Optional `--dynamic` uses Docker before installation.
4. Retains the verified archive at `.unsus/artifacts/<sha512>.tgz` inside your project and passes that archive to npm with `--ignore-scripts` and an explicit local project prefix, overriding global/prefix configuration. This flag also disables transitive and project lifecycle scripts during that install, even when ordinary npm configuration enables them.

**Keep and commit `.unsus/artifacts/` with `package.json` and `package-lock.json`.** npm records a relative `file:` dependency to this archive, so deleting it breaks reproducible installs. Treat these as vendored dependencies; the installer never garbage-collects them automatically. Updating a package through `unsus install` produces a new archive and dependency reference. Do not publish a library expecting consumers to resolve your private artifact path.

Later installs must also use `npm ci --ignore-scripts` or `npm install --ignore-scripts`. unsus does not change your persistent npm settings. Packages that depend on build/install hooks may remain unusable until separately reviewed and built. `--force` never enables lifecycle scripts and cannot bypass checksum or extraction failures. Transitive dependencies are resolved by npm and **are not scanned**.

## Analysis and limits

Static heuristics inspect lifecycle metadata, source patterns with JavaScript token context, imported child-process bindings, credential/network/filesystem access patterns, dynamic evaluation, obfuscation, binary indicators and version changes. Comments, string examples and TypeScript declaration files do not count as executed API calls. This is not full semantic or data-flow analysis: unusual aliases, computed properties, shadowed bindings and unsupported typed-source syntax can be missed or misclassified; an unparsed tail falls back to conservative pattern matching. Isolated capabilities and accumulated documentation noise require review rather than automatically blocking. Explicit behavioral chains and dense-source obfuscation rules still block. Published `dist/` files are included. Individual text files above 256 KiB or containing NUL bytes are omitted and make the report warn. Unknown formats receive limited inspection. Version diffs hash complete contents, including omitted text and binaries, so local diffs can read large files in full; ordinary scans keep bounded text/header reads. Local `.git`, `node_modules` and symbolic links are skipped; bundled dependencies inside `node_modules` are not analyzed.

Registry downloads and metadata are capped at 20 MiB with a 30-second request timeout. Archive inflation is capped at 100 MiB, individual entries at 10 MiB and entries at 10,000. Links, special files, traversal, duplicate/case-colliding paths and inconsistent package identities are rejected. These conservative limits may reject legitimate packages. Registry metadata and tarball URLs must use HTTPS, must not contain credentials, and redirects are rejected. The only HTTP exception is the explicitly configured loopback registry origin. Private registry authentication and registries requiring redirects are not supported in this release. The default is `https://registry.npmjs.org`; installer `--registry` supports compatible registries (HTTP is allowed only for explicitly configured loopback testing).

Dynamic observation runs lifecycle scripts in a copied workspace with Docker networking disabled, limited CPU/memory/processes, no host credentials passed as environment variables, and a read-only container root. Prepare the image with `docker pull node:22-bookworm-slim`. Docker absence, daemon failure and launch failure stop a requested dynamic run; execution never falls back to the host. Containers are created before scripts start. Every started container is removed with a bounded deadline and its absence is confirmed before workspace cleanup. If creation or teardown cannot be confirmed, the command fails and retains the named temporary workspace for manual cleanup. Remote dynamic scans require `--allow-remote-dynamic`; `install --dynamic` explicitly opts in for that registry package. Dynamic mode does not install dependencies and may report build failures from missing tools.

Docker observation is experimental. There is no syscall tracing, network-attempt detection, malware reverse engineering, sandbox-escape detection, full provenance verification or complete vulnerability database. It is not a proven boundary for hostile samples. Development and CI use harmless synthetic packages only.

## Development and release checks

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
npm run benchmark:synthetic
npm run verify:release
```

Tests include a loopback registry and a real npm install with harmless root, direct and transitive lifecycle markers; none may execute. They also cover tampered archives, missing checksums, extraction limits, symbolic links and package identity mismatches. Synthetic benchmark scores describe these fixtures only, not real-world detection rates.

Historical research and disposable-lab documentation remains under `docs/` and `scripts/research/`; it is separate from the v0.1 product path and is not needed for onboarding. Do not fetch or execute real malicious samples on a development machine.
