import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, cp, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { Finding, SandboxResult, SandboxTimelineEvent } from "@unsus/core";

export interface DockerRunOptions {
  image: string;
  workspacePath: string;
  command: string[];
  memory?: string;
  cpus?: string;
  pidsLimit?: number;
  readOnly?: boolean;
  containerName?: string;
  env?: Record<string, string>;
}

export function buildDockerRunArgs(options: DockerRunOptions): string[] {
  return [
    "run",
    "--rm",
    ...(options.containerName ? ["--name", options.containerName] : []),
    "--network=none",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    `--memory=${options.memory ?? "512m"}`,
    `--cpus=${options.cpus ?? "1"}`,
    `--pids-limit=${options.pidsLimit ?? 128}`,
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=64m",
    ...(options.readOnly ?? true ? ["--read-only"] : []),
    "--mount",
    `type=bind,src=${options.workspacePath},dst=/workspace,readonly=false`,
    "--workdir",
    "/workspace",
    "--env",
    "HOME=/tmp",
    "--env",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ...Object.entries(options.env ?? {}).flatMap(([key, value]) => ["--env", `${key}=${value}`]),
    options.image,
    ...options.command
  ];
}

export interface DockerExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export type DockerExecutor = (args: string[], options: { timeoutMs: number; containerName: string }) => Promise<DockerExecutionResult>;

export interface LifecycleSandboxOptions {
  sourceRootPath: string;
  packageJson: Record<string, unknown>;
  image?: string;
  timeoutMs?: number;
  dockerExecutor?: DockerExecutor;
}

const LIFECYCLE_ORDER = ["preinstall", "install", "postinstall", "prepare"];
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "coverage"]);
const OUTPUT_LIMIT = 4096;

export async function runLifecycleScriptsInDockerSandbox(options: LifecycleSandboxOptions): Promise<SandboxResult> {
  const startedAt = Date.now();
  const timeline: SandboxTimelineEvent[] = [
    event(startedAt, "sandbox_started", "sandbox started")
  ];
  const findings: Finding[] = [
    {
      id: "sandbox.network_detection_unsupported",
      category: "sandbox_behavior",
      type: "network_detection_unsupported",
      severity: "info",
      title: "Network attempt detection unsupported",
      message: "This sandbox version runs with --network=none but does not yet trace attempted network syscalls.",
      confidence: 1
    }
  ];

  timeline.push(event(startedAt, "network_detection_unsupported", "network-attempt detection is unsupported in this version"));

  const scripts = lifecycleScripts(options.packageJson);
  if (scripts.length === 0) {
    timeline.push(event(startedAt, "lifecycle_scripts_absent", "no lifecycle scripts detected"));
    return {
      enabled: true,
      timedOut: false,
      exitCode: 0,
      timeline,
      findings
    };
  }

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "unsus-sandbox-"));
  const workspacePath = path.join(tempRoot, "workspace");

  try {
    await copyWorkspace(options.sourceRootPath, workspacePath);
    let before = await snapshotWorkspace(workspacePath);
    let finalExitCode = 0;
    let timedOut = false;

    for (const script of scripts) {
      timeline.push(
        event(startedAt, "lifecycle_script_detected", `detected ${script.name} script: ${script.command}`, {
          script: script.name,
          command: script.command
        })
      );

      const containerName = `unsus-sandbox-${randomUUID()}`;
      const args = buildDockerRunArgs({
        image: options.image ?? "node:22-bookworm-slim",
        workspacePath,
        command: ["sh", "-lc", script.command],
        containerName,
        env: {
          FAKE_TEST_TOKEN: "unsus-fake-token"
        }
      });

      const executor = options.dockerExecutor ?? executeDocker;
      const result = await executor(args, {
        timeoutMs: options.timeoutMs ?? 5000,
        containerName
      });

      finalExitCode = result.exitCode;
      timedOut = timedOut || result.timedOut;
      timeline.push(
        event(startedAt, "lifecycle_script_executed", `${script.name} script exited with code ${result.exitCode}`, {
          script: script.name,
          exitCode: result.exitCode,
          stdout: truncate(result.stdout),
          stderr: truncate(result.stderr)
        })
      );

      if (result.timedOut) {
        findings.push({
          id: `sandbox.timeout.${script.name}`,
          category: "sandbox_behavior",
          type: "sandbox_timeout",
          severity: "danger",
          title: "Sandbox lifecycle script timed out",
          message: `${script.name} script exceeded sandbox timeout.`,
          evidence: { script: script.name },
          confidence: 0.9
        });
        timeline.push(event(startedAt, "sandbox_timeout", `${script.name} script timed out`));
        break;
      }

      const after = await snapshotWorkspace(workspacePath);
      for (const change of diffSnapshots(before, after)) {
        timeline.push(event(startedAt, change.type, `${change.label} inside workspace: ${change.path}`, { path: change.path }));
      }
      before = after;

      if (result.exitCode !== 0) {
        findings.push({
          id: `sandbox.nonzero_exit.${script.name}`,
          category: "sandbox_behavior",
          type: "sandbox_nonzero_exit",
          severity: "warning",
          title: "Lifecycle script exited non-zero",
          message: `${script.name} script exited with code ${result.exitCode}.`,
          evidence: { script: script.name, exitCode: result.exitCode },
          confidence: 0.8
        });
        break;
      }
    }

    return {
      enabled: true,
      timedOut,
      exitCode: finalExitCode,
      timeline,
      findings
    };
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
}

async function executeDocker(args: string[], options: { timeoutMs: number; containerName: string }): Promise<DockerExecutionResult> {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin"
      }
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
      void forceRemoveContainer(options.containerName);
    }, options.timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        exitCode: code ?? (timedOut ? 137 : 1),
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        timedOut
      });
    });
  });
}

async function forceRemoveContainer(containerName: string): Promise<void> {
  await new Promise<void>((resolve) => {
    const child = spawn("docker", ["rm", "-f", containerName], {
      stdio: "ignore",
      env: {
        PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin"
      }
    });
    child.on("close", () => resolve());
    child.on("error", () => resolve());
  });
}

function lifecycleScripts(packageJson: Record<string, unknown>): Array<{ name: string; command: string }> {
  const scripts = packageJson.scripts;
  if (typeof scripts !== "object" || scripts === null || Array.isArray(scripts)) {
    return [];
  }

  return LIFECYCLE_ORDER.flatMap((name) => {
    const command = (scripts as Record<string, unknown>)[name];
    return typeof command === "string" ? [{ name, command }] : [];
  });
}

async function copyWorkspace(sourceRootPath: string, workspacePath: string): Promise<void> {
  await cp(sourceRootPath, workspacePath, {
    recursive: true,
    filter: (source) => !SKIP_DIRS.has(path.basename(source))
  });
}

interface SnapshotEntry {
  size: number;
  mtimeMs: number;
}

async function snapshotWorkspace(rootPath: string): Promise<Map<string, SnapshotEntry>> {
  const files = new Map<string, SnapshotEntry>();

  async function walk(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) {
        continue;
      }

      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(absolutePath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const currentStat = await stat(absolutePath);
      const relativePath = path.relative(rootPath, absolutePath).split(path.sep).join("/");
      files.set(relativePath, {
        size: currentStat.size,
        mtimeMs: currentStat.mtimeMs
      });
    }
  }

  await walk(rootPath);
  return files;
}

function diffSnapshots(
  before: Map<string, SnapshotEntry>,
  after: Map<string, SnapshotEntry>
): Array<{ type: "file_created" | "file_modified"; label: string; path: string }> {
  const changes: Array<{ type: "file_created" | "file_modified"; label: string; path: string }> = [];
  for (const [filePath, afterEntry] of after.entries()) {
    const beforeEntry = before.get(filePath);
    if (!beforeEntry) {
      changes.push({ type: "file_created", label: "file created", path: filePath });
      continue;
    }

    if (beforeEntry.size !== afterEntry.size || beforeEntry.mtimeMs !== afterEntry.mtimeMs) {
      changes.push({ type: "file_modified", label: "file modified", path: filePath });
    }
  }

  return changes;
}

function event(
  startedAt: number,
  type: string,
  message: string,
  evidence?: Record<string, unknown>
): SandboxTimelineEvent {
  return {
    timeMs: Date.now() - startedAt,
    type,
    message,
    ...(evidence ? { evidence } : {})
  };
}

function truncate(value: string): string {
  return value.length <= OUTPUT_LIMIT ? value : `${value.slice(0, OUTPUT_LIMIT)}...<truncated>`;
}
