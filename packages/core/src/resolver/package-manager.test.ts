import assert from "node:assert/strict";
import { test } from "node:test";

import { isNpmPackageRequest, parsePackageRequest } from "./package-manager.js";

test("parsePackageRequest handles unscoped latest, exact versions, ranges, and scoped packages", () => {
  assert.deepEqual(parsePackageRequest("left-pad"), { name: "left-pad", requested: "latest" });
  assert.deepEqual(parsePackageRequest("left-pad@1.3.0"), { name: "left-pad", requested: "1.3.0" });
  assert.deepEqual(parsePackageRequest("left-pad@^1.0.0"), { name: "left-pad", requested: "^1.0.0" });
  assert.deepEqual(parsePackageRequest("@scope/pkg@2.0.0"), { name: "@scope/pkg", requested: "2.0.0" });
});

test("isNpmPackageRequest accepts scoped packages but rejects local paths", () => {
  assert.equal(isNpmPackageRequest("@fairwords/websocket@1.0.38"), true);
  assert.equal(isNpmPackageRequest("@scope/pkg"), true);
  assert.equal(isNpmPackageRequest("left-pad@1.3.0"), true);
  assert.equal(isNpmPackageRequest("./fixtures/pkg"), false);
  assert.equal(isNpmPackageRequest("/tmp/pkg"), false);
  assert.equal(isNpmPackageRequest("fixtures/pkg"), false);
  assert.equal(isNpmPackageRequest("../pkg"), false);
  assert.equal(isNpmPackageRequest("pkg\\dir"), false);
});
