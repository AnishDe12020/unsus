import assert from "node:assert/strict";
import { test } from "node:test";
import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { buildDockerRunArgs, runLifecycleScriptsInDockerSandbox } from "./docker.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("buildDockerRunArgs includes no-network and hardening flags", () => {
  const args = buildDockerRunArgs({
    image: "unsus-sandbox:test",
    workspacePath: "/tmp/workspace",
    command: ["node", "install.js"]
  });

  assert.ok(args.includes("--network=none"));
  assert.ok(args.includes("--cap-drop=ALL"));
  assert.ok(args.includes("--security-opt=no-new-privileges"));
  assert.ok(args.includes("--pids-limit=128"));
  assert.ok(args.includes("--read-only"));
  assert.ok(args.includes("--user"));
  assert.ok(args.includes("0:0"));
  assert.ok(args.some((arg) => arg.startsWith("type=bind,") && !arg.includes("readonly")));
});

test("runLifecycleScriptsInDockerSandbox uses copied workspace and records file changes", async () => {
  const fixturePath = path.join(repoRoot, "fixtures/benign/install-script-build-package");
  const result = await runLifecycleScriptsInDockerSandbox({
    sourceRootPath: fixturePath,
    packageJson: {
      scripts: {
        postinstall: "node postinstall.js"
      }
    },
    dockerExecutor: async (args) => {
      const workspacePath = workspacePathFromArgs(args);
      const workspaceStat = await import("node:fs/promises").then((fs) => fs.stat(workspacePath));
      assert.equal(workspaceStat.mode & 0o777, 0o777);
      await import("node:fs/promises").then((fs) =>
        fs.writeFile(path.join(workspacePath, "build-marker.txt"), "created in temp workspace\n")
      );
      return {
        exitCode: 0,
        stdout: "fixture stdout",
        stderr: "",
        timedOut: false
      };
    }
  });

  assert.equal(result.enabled, true);
  assert.equal(result.exitCode, 0);
  assert.ok(result.timeline.some((event) => event.type === "file_created" && event.message.includes("build-marker.txt")));
  await assert.rejects(access(path.join(fixturePath, "build-marker.txt"), constants.F_OK));
});

test("runLifecycleScriptsInDockerSandbox records timeout", async () => {
  const fixturePath = path.join(repoRoot, "fixtures/benign/install-script-build-package");
  const result = await runLifecycleScriptsInDockerSandbox({
    sourceRootPath: fixturePath,
    packageJson: {
      scripts: {
        postinstall: "node postinstall.js"
      }
    },
    dockerExecutor: async () => ({
      exitCode: 137,
      stdout: "",
      stderr: "timed out",
      timedOut: true
    })
  });

  assert.equal(result.timedOut, true);
  assert.ok(result.findings.some((finding) => finding.type === "sandbox_timeout"));
});

test("runLifecycleScriptsInDockerSandbox rejects Docker infrastructure failures", async () => {
  const fixturePath = path.join(repoRoot, "fixtures/benign/install-script-build-package");

  await assert.rejects(
    runLifecycleScriptsInDockerSandbox({
      sourceRootPath: fixturePath,
      packageJson: {
        scripts: {
          postinstall: "node postinstall.js"
        }
      },
      dockerExecutor: async () => ({
        exitCode: 1,
        stdout: "",
        stderr: "Cannot connect to the Docker daemon at unix:///tmp/docker.sock. Is the docker daemon running?",
        timedOut: false
      })
    }),
    /Docker sandbox infrastructure failure/
  );
});

function workspacePathFromArgs(args: string[]): string {
  const mountIndex = args.indexOf("--mount");
  assert.notEqual(mountIndex, -1);
  const mountSpec = args[mountIndex + 1] ?? "";
  const src = mountSpec
    .split(",")
    .find((part) => part.startsWith("src="))
    ?.slice("src=".length);
  assert.ok(src);
  return src;
}
