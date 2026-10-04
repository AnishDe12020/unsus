# @unsus/core

Static npm-package heuristics, integrity-verified registry downloads, bounded archive extraction, risk reports and version diffs. Requires Node.js 22 or newer.

```js
import { scanTarget } from '@unsus/core';
const report = await scanTarget('./package-directory');
console.log(report.coverage, report.findings);
```

Only the direct package is analyzed. Findings are heuristics, not proof of safety. Runtime behavior and transitive dependencies are not covered. Large text files are reported as omitted. See the [repository documentation](https://github.com/AnishDe12020/unsus#readme) for limitations and the guarded CLI installer.
