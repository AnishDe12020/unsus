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

2. If the risk score is **medium or higher** (>3.0), investigate the flagged findings:
   - Read the specific files and lines referenced in each finding
   - Determine if each finding is a **true positive** (actually malicious) or **false positive** (legitimate usage)
   - Explain your reasoning for each finding

3. Summarize:
   - Overall risk assessment (safe to use or not)
   - Which findings are real concerns vs noise
   - If suspicious, what the package appears to be doing (data exfil, cryptomining, backdoor, etc.)

## Notes

- The scanner runs static analysis + threat intel (URLhaus/VirusTotal) by default
- Add `--no-dynamic` if Docker isn't available
- Add `--json` if you need structured output for further processing
- If scanning a local directory instead of an npm package name, pass the path directly
