# @unsus/cli

Heuristic npm package scanner and guarded npm installer. Requires Node.js 22+ and npm.

```sh
unsus scan ./package-directory --json
unsus scan package-name@1.2.3
unsus diff package-name@1.2.3 --against package-name@1.2.2 --registry https://registry.npmjs.org
unsus project . --include-dev --json
unsus install package-name@1.2.3
```

The installer verifies registry checksums, scans the direct package, and installs its exact retained tarball with lifecycle scripts disabled across the npm install. It supports npm registry names/versions only. It does not analyze transitive dependencies or make runtime code safe.

`project` inspects installed direct dependencies offline, without installing or executing them. Missing, linked, unsupported and omitted packages are reported as coverage gaps. It does not verify installed files against registry or lockfile integrity. The default limit is 20 attempted packages; `--max-packages` accepts 1–100. Use `--include-dev` to include development dependencies. Gaps require review (exit 1); blocked findings exit 2, and inspection failures take exit 3.

`scan`, `diff`, and `install` share `--registry URL`. In JSON mode operational failures emit `{ok:false, exitCode:3, error:{code,message}}`; failed installs include their scan as `report`. Errors use stderr when `--output` or SARIF is selected, preserving any existing report file.

Archive dependencies are saved as `file:.unsus/artifacts/<sha512>.tgz`. Keep and commit those artifacts alongside package.json and package-lock.json. Later installs must also use `npm ci --ignore-scripts` or `npm install --ignore-scripts`. No persistent npm policy is changed.

Exit codes: 0 allowed/completed, 1 review warning, 2 blocked, 3 operational failure. `--force` bypasses findings only; it never bypasses integrity verification or enables scripts. Full usage and limits: [repository documentation](https://github.com/AnishDe12020/unsus#readme).
