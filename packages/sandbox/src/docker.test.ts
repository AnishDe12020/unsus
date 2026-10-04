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

test("sandbox rejects copied symbolic links without changing external file permissions", async () => {
  const fs = await import("node:fs/promises");
  const os = await import("node:os");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-test-sandbox-"));
  try {
    const source = path.join(root, "source");
    await fs.mkdir(source);
    const outside = path.join(root, "outside.txt");
    await fs.writeFile(outside, "fixture", { mode: 0o600 });
    await fs.symlink(outside, path.join(source, "link"));
    await assert.rejects(runLifecycleScriptsInDockerSandbox({ sourceRootPath: source, packageJson: { scripts: { postinstall: "echo fixture" } }, dockerExecutor: async () => ({ exitCode: 0, stdout: "", stderr: "", timedOut: false }) }), /symbolic link/i);
    assert.equal((await fs.stat(outside)).mode & 0o777, 0o600);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("sandbox treats Docker exit 125 as infrastructure failure", async () => {
  await assert.rejects(runLifecycleScriptsInDockerSandbox({ sourceRootPath: path.join(repoRoot, "fixtures/benign/install-script-build-package"), packageJson: { scripts: { postinstall: "echo fixture" } }, dockerExecutor: async () => ({ exitCode: 125, stdout: "", stderr: "image unavailable", timedOut: false }) }), /infrastructure failure/i);
});

test("real executor awaits teardown and retains workspace when container absence is unconfirmed", async () => {
  const fs = await import("node:fs/promises");
  const os = await import("node:os");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "unsus-test-docker-executor-"));
  const oldPath = process.env.PATH;
  try {
    const fakeDocker = `#!${process.execPath}\nconst fs=require('fs');const path=require('path');const root=${JSON.stringify(root)};const args=process.argv.slice(2);fs.appendFileSync(path.join(root,'calls'),args[0]+'\\n');if(args[0]==='create'||args[0]==='run'){const mount=args[args.indexOf('--mount')+1];fs.writeFileSync(path.join(root,'workspace'),mount.split(',').find(x=>x.startsWith('src=')).slice(4));}if(args[0]==='create'){console.log('synthetic-container-id');}else if(args[0]==='start'||args[0]==='run'){setInterval(()=>{},1000);}else if(args[0]==='rm'){setTimeout(()=>{if(fs.existsSync(path.join(root,'fail'))){console.error('synthetic daemon unavailable');process.exitCode=1;}else{fs.writeFileSync(path.join(root,'removed'),'yes');}},100);}else if(args[0]==='inspect'){console.error('Error: No such object: synthetic');process.exitCode=1;}`;
    await fs.writeFile(path.join(root, "docker"), fakeDocker, { mode: 0o755 });
    process.env.PATH = `${root}${path.delimiter}${oldPath}`;
    const options = { sourceRootPath: path.join(repoRoot, "fixtures/benign/install-script-build-package"), packageJson: { scripts: { postinstall: "echo harmless" } }, timeoutMs: 500 };
    const result = await runLifecycleScriptsInDockerSandbox(options);
    assert.equal(result.timedOut, true);
    assert.equal(await fs.readFile(path.join(root, "removed"), "utf8"), "yes", "runner must not return before removal completes");
    assert.match(await fs.readFile(path.join(root, "calls"), "utf8"), /^create\nstart\nrm\ninspect\n$/);
    await fs.writeFile(path.join(root, "fail"), "yes");
    await assert.rejects(runLifecycleScriptsInDockerSandbox(options), /cleanup|teardown|absence/i);
    const workspace = await fs.readFile(path.join(root, "workspace"), "utf8");
    await fs.access(workspace);
    await fs.rm(path.dirname(workspace), { recursive: true, force: true });
  } finally {
    if (oldPath === undefined) delete process.env.PATH; else process.env.PATH = oldPath;
    await fs.rm(root, { recursive: true, force: true });
  }
});
