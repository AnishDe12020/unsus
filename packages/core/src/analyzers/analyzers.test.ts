import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { extractLocalPackage } from "../extract/local.js";
import { analyzeAst } from "./ast.js";
import { analyzeBinary } from "./binary.js";
import { analyzeEntropy } from "./entropy.js";
import { analyzeIocs } from "./ioc.js";
import { analyzeMetadata } from "./metadata.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");

test("metadata analyzer detects lifecycle scripts and suspicious shell fragments", async () => {
  const extracted = await extractLocalPackage(path.join(repoRoot, "fixtures/suspicious/postinstall-env-network"));
  const findings = analyzeMetadata(extracted);

  assert.ok(findings.some((finding) => finding.type === "lifecycle_script"));
  assert.ok(findings.some((finding) => finding.category === "install_time_execution"));
});

test("AST analyzer detects env access, network APIs, dynamic code, and child process use", async () => {
  const envNetwork = await extractLocalPackage(path.join(repoRoot, "fixtures/suspicious/postinstall-env-network"));
  const obfuscated = await extractLocalPackage(path.join(repoRoot, "fixtures/suspicious/obfuscated-eval"));
  const childProcess = await extractLocalPackage(path.join(repoRoot, "fixtures/suspicious/child-process-install"));

  const findings = [
    ...analyzeAst(envNetwork),
    ...analyzeAst(obfuscated),
    ...analyzeAst(childProcess)
  ];

  assert.ok(findings.some((finding) => finding.type === "process_env_access"));
  assert.ok(findings.some((finding) => finding.type === "network_api"));
  assert.ok(findings.some((finding) => finding.type === "eval_call"));
  assert.ok(findings.some((finding) => finding.type === "base64_decode"));
  assert.ok(findings.some((finding) => finding.type === "child_process_import"));
  assert.ok(findings.some((finding) => finding.type === "child_process_execution"));
});

test("entropy, IOC, and binary analyzers report high-signal static findings", async () => {
  const obfuscated = await extractLocalPackage(path.join(repoRoot, "fixtures/suspicious/obfuscated-eval"));
  const envNetwork = await extractLocalPackage(path.join(repoRoot, "fixtures/suspicious/postinstall-env-network"));

  assert.ok(analyzeEntropy(obfuscated).some((finding) => finding.type === "high_entropy_string"));
  assert.ok(analyzeIocs(envNetwork).some((finding) => finding.type === "url_literal"));
  assert.equal(analyzeBinary(envNetwork).some((finding) => finding.category === "binary_payload"), false);
});
