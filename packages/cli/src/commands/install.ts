import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile, lstat } from "node:fs/promises";
import path from "node:path";

import { formatJsonReport, formatScanText, isNpmPackageRequest, resolveNpmPackage, scanPackage } from "@unsus/core";
import { runLifecycleScriptsInDockerSandbox } from "@unsus/sandbox";
import { readOption } from "./scan.js";

export async function runInstallCommand(args: string[]): Promise<number> {
  const valueOptions = new Set(["--pm", "--registry"]);
  const flags = new Set(["--force", "--json", "--yes", "--dynamic"]);
  const targets: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (valueOptions.has(arg)) {
      if (!args[index + 1] || args[index + 1]!.startsWith("--")) throw new Error(`Missing value for ${arg}.`);
      index++;
    } else if (flags.has(arg)) continue;
    else if (arg.startsWith("-")) throw new Error(`Unsupported install option: ${arg}`);
    else targets.push(arg);
  }
  if (targets.length !== 1) throw new Error("Usage: unsus install <registry-package> [--registry URL] [--dynamic] [--force] [--json] [--yes]");
  const target = targets[0]!;
  const pm = readOption(args, "--pm") ?? "npm";
  if (pm !== "npm") throw new Error("This release supports npm only. Use --pm npm; bun and pnpm installation are not supported.");
  if (!isNpmPackageRequest(target)) throw new Error("Install requires an npm registry package name or version. Local paths, Git URLs and tarball URLs are not supported; use unsus scan for local analysis.");
  // Require a project so archive references and lockfiles have a stable home.
  await readFile(path.resolve("package.json"), "utf8");
  const registry = readOption(args, "--registry");
  const pkg = await resolveNpmPackage(target, registry ? { registry } : {});
  try {
    const dynamic = args.includes("--dynamic");
    const result = await scanPackage(pkg, {
      dynamic,
      allowRemoteDynamic: dynamic,
      ...(dynamic ? { dynamicRunner: (resolved) => runLifecycleScriptsInDockerSandbox({ sourceRootPath: resolved.rootPath, packageJson: resolved.packageJson }) } : {})
    });
    process.stdout.write(args.includes("--json") ? formatJsonReport(result) : formatScanText(result));
    if (result.decision === "block" && !args.includes("--force")) {
      console.error("Install blocked by unsus policy. Use --force only after manual review.");
      return 2;
    }
    if (result.decision === "warn" && !args.includes("--yes") && !args.includes("--force")) {
      console.error("Install requires --yes after reviewing warnings.");
      return 1;
    }
    if (args.includes("--force")) console.error("FORCE OVERRIDE: findings accepted; lifecycle scripts remain disabled.");
    if (!pkg.tarballPath) throw new Error("Verified registry archive is unavailable.");
    const bytes = await readFile(pkg.tarballPath);
    const digest = createHash("sha512").update(bytes).digest("hex");
    for (const directory of [".unsus", ".unsus/artifacts"]) {
      await mkdir(directory, { recursive: true });
      if (!(await lstat(directory)).isDirectory()) throw new Error("Artifact directory must not be a symbolic link.");
    }
    const relativeArchive = `.unsus/artifacts/${digest}.tgz`;
    try { await writeFile(relativeArchive, bytes, { flag: "wx", mode: 0o600 }); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (!(await lstat(relativeArchive)).isFile() || !(await readFile(relativeArchive)).equals(bytes)) throw new Error("Existing artifact differs from the verified archive; refusing to overwrite it.");
    }
    console.error("Installing verified direct-package archive with all lifecycle scripts disabled. Transitive dependencies were not scanned. Keep .unsus/artifacts with package.json and the lockfile.");
    const exitCode = await runPackageManagerInstall(relativeArchive, registry, args.includes("--json"));
    return exitCode === 0 ? 0 : 3;
  } finally { await pkg.cleanup?.(); }
}

function runPackageManagerInstall(archive: string, registry: string | undefined, json: boolean): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn("npm", ["install", "--ignore-scripts", "--save-exact", "--no-audit", "--no-fund", ...(registry ? ["--registry", registry] : []), "--", `./${archive}`], {
      // Keep --json stdout machine-readable; npm status belongs on stderr.
      stdio: ["inherit", json ? 2 : "inherit", "inherit"],
      env: { ...process.env, npm_config_ignore_scripts: "true" }
    });
    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 1));
  });
}
