import assert from "node:assert/strict";
import { test } from "node:test";

import { parsePackageRequest } from "./package-manager.js";

test("parsePackageRequest handles unscoped latest, exact versions, ranges, and scoped packages", () => {
  assert.deepEqual(parsePackageRequest("left-pad"), { name: "left-pad", requested: "latest" });
  assert.deepEqual(parsePackageRequest("left-pad@1.3.0"), { name: "left-pad", requested: "1.3.0" });
  assert.deepEqual(parsePackageRequest("left-pad@^1.0.0"), { name: "left-pad", requested: "^1.0.0" });
  assert.deepEqual(parsePackageRequest("@scope/pkg@2.0.0"), { name: "@scope/pkg", requested: "2.0.0" });
});
