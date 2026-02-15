# unsus

npm supply chain malware detector. Scans packages for malicious patterns using static analysis, dynamic sandboxing, threat intelligence, and AI-powered code review.

## Quick start

```bash
bun install
```

### Scan a package

```bash
bun run src/index.ts scan axios           # fetch from npm + scan
bun run src/index.ts scan ./my-package    # scan local directory
```

### Scan before installing

```bash
bun run src/index.ts install axios lodash   # scan, then install if clean
```

### Web dashboard

```bash
bun --hot src/dashboard/server.ts           # http://localhost:3000
```

## What it detects

**6 static analyzers** run in parallel:

| Analyzer | What it catches |
|----------|----------------|
| npm audit | Known CVEs in dependency tree |
| Metadata | Install scripts, typosquatting, base64 in package.json |
| AST | eval, child_process, network calls, env access, dynamic require |
| Entropy | Obfuscated/encrypted strings (Shannon entropy > 5.0 bits/char) |
| Regex IOC | URLs, IPs, domains, crypto wallets (ETH, BTC, SOL, TRX) |
| Binary | ELF/PE/Mach-O executables, cryptominer binaries, mining pools |

**Threat intel** — extracted IOCs checked against URLhaus (abuse.ch) and optionally VirusTotal.

**Dynamic analysis** (default, requires Docker) — runs `npm install` in a hardened container (`--network=none`, `--read-only`, `--cap-drop=ALL`) and monitors:
- Outbound network attempts (via net-hook.js patching `net.Socket.connect`)
- CPU/memory spikes (cryptominer detection)
- Filesystem changes outside `node_modules`

**AI analysis** (default, requires [Claude CLI](https://github.com/anthropics/claude-code)) — sends source code + findings to Claude for independent review. Blended final score: scanner 40% + AI 60%.

## Scoring

Diminishing returns — each additional finding of the same severity contributes less. Compound multipliers for dangerous combos (e.g. install-script + network = x1.3, obfuscation + exec = x1.5). Score 0-10, mapped to safe/low/medium/high/critical.

## Flags

```
--no-dynamic          skip Docker sandbox
--no-ai               skip AI analysis
--ai-provider <p>     AI backend: claude|gemini|codex|auto (default: auto)
--fail-on <level>     exit 1 if risk >= level (default: high)
--json                raw JSON output
--dry-run             (install only) scan without installing
--pm <manager>        (install only) force bun/npm/yarn/pnpm
```

## Architecture

See [docs/how-it-works.md](docs/how-it-works.md) for the full technical breakdown.

## Requirements

- [Bun](https://bun.sh) v1.2+
- Docker (for dynamic analysis)
- [Claude CLI](https://github.com/anthropics/claude-code) (for AI analysis, optional)
