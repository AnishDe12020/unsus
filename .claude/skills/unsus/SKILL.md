---
name: unsus
description: Scan an npm package for supply chain malware, obfuscation, and suspicious behavior
argument-hint: <package-name>
allowed-tools: Bash(bun:*), Read, Glob, Grep
---

Scan the npm package `$ARGUMENTS` for supply chain threats using unsus.

## Steps

1. Run the scan:
```
bun src/index.ts scan $ARGUMENTS
```

2. Review the output:
   - **Scanner results**: Static analysis findings with severity levels and a risk score (0-10)
   - **AI analysis** (if available): Independent code review by Claude/Gemini/Codex that cross-checks scanner findings against actual code behavior

3. If the risk score is **medium or higher** (>3.0) OR the AI verdict is SUSPICIOUS/MALICIOUS, investigate:
   - Read the specific files and lines referenced in each finding
   - For each finding, determine: is this a **true positive** (actually malicious behavior) or a **false positive** (legitimate usage that triggered a pattern match)?
   - Pay special attention to: install scripts, network calls during install, data exfiltration patterns, obfuscated code that decodes to shell commands
   - Common false positives to watch for: base64 in auth/encoding, dynamic require in plugin systems, network calls in HTTP libraries, minified vendor files

4. Summarize with a clear verdict:
   - **SAFE**: All findings are false positives, package is legitimate
   - **SUSPICIOUS**: Some patterns warrant caution but no confirmed malice — recommend manual review
   - **MALICIOUS**: Evidence of data theft, backdoors, cryptomining, or other supply chain attacks — do NOT install
   - List which specific findings are real concerns vs noise, with reasoning

## Options

- `--no-dynamic` — skip Docker sandbox analysis (if Docker isn't available)
- `--no-ai` — skip AI analysis, scanner only
- `--ai-provider <claude|gemini|codex>` — choose AI provider (default: auto-detect)
- `--json` — structured JSON output for further processing
- A local directory path can be passed instead of an npm package name
