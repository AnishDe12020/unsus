import { readdir } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";

const repoRoot = process.cwd();
const packageRoot = path.join(repoRoot, "packages");
const testFiles = [];

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await walk(absolutePath);
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(".test.ts") && absolutePath.includes(`${path.sep}src${path.sep}`)) {
      testFiles.push(absolutePath.replace(`${path.sep}src${path.sep}`, `${path.sep}dist${path.sep}`).replace(/\.ts$/, ".js"));
    }
  }
}

await walk(packageRoot);
testFiles.sort();

if (testFiles.length === 0) {
  console.error("No compiled test files found. Run npm run build or check TypeScript build outputs.");
  process.exit(1);
}

const child = spawn(process.execPath, ["--test", ...testFiles], {
  stdio: "inherit"
});

child.on("exit", (code, signal) => {
  if (signal) {
    console.error(`node --test exited via signal ${signal}`);
    process.exit(1);
  }

  process.exit(code ?? 1);
});
