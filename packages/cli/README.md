# @unsus/cli

Heuristic npm package scanner and guarded npm installer. Requires Node.js 22+ and npm.

```sh
unsus scan ./package-directory --json
unsus scan package-name@1.2.3
unsus install package-name@1.2.3
```

The installer verifies registry checksums, scans the direct package, and installs its exact retained tarball with lifecycle scripts disabled across the npm install. It supports npm registry names/versions only. It does not analyze transitive dependencies or make runtime code safe.

Archive dependencies are saved as `file:.unsus/artifacts/<sha512>.tgz`. Keep and commit those artifacts alongside package.json and package-lock.json. Later installs must also use `npm ci --ignore-scripts` or `npm install --ignore-scripts`. No persistent npm policy is changed.

Exit codes: 0 allowed/completed, 1 review warning, 2 blocked, 3 operational failure. `--force` bypasses findings only; it never bypasses integrity verification or enables scripts. Full usage and limits: [repository documentation](https://github.com/AnishDe12020/unsus#readme).
