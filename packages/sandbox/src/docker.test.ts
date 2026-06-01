import assert from "node:assert/strict";
import { test } from "node:test";

import { buildDockerRunArgs } from "./docker.js";

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
});
