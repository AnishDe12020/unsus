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
import { scanExtractedPackage } from "../scan.js";

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

test("execution signals distinguish regex, comments and declarations from imported child-process calls", async () => {
  const pkg = await extractLocalPackage(path.join(repoRoot, "fixtures/benign/normal-package"));
  const inspect = (file: string, content: string) => analyzeAst({ ...pkg, files: [{ path: file, content, size: content.length, kind: "source" }] });
  assert.deepEqual(inspect("index.js", 'const re = /hello/; re.exec("hello"); // eval("documentation"); process.env.SECRET\nconst example = "spawn(command)";'), []);
  assert.deepEqual(inspect("index.d.ts", 'declare function exec(command: string): void; /** eval(code); process.env.SECRET */'), []);
  const actual = inspect("index.js", 'import { exec as run } from "node:child_process"; run("echo fixture"); /x/.exec("x");');
  assert.equal(actual.filter(finding => finding.type === "child_process_execution").length, 1);
  assert.ok(actual.some(finding => finding.type === "child_process_import"));
  const blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".repeat(4);
  const typedSource = `// "${blob}"\n@decorator\nclass Example { payload = "${blob}"; }`;
  const tail = analyzeEntropy({ ...pkg, files: [{ path: "decorated.ts", content: typedSource, size: typedSource.length, kind: "source" }] });
  assert.equal(tail.filter(finding => finding.type === "high_entropy_string").length, 1);
});

test("passive parser tables require review while executable chains and encoded payloads still block", async () => {
  const pkg = await extractLocalPackage(path.join(repoRoot, "fixtures/benign/normal-package"));
  const ranges = Array.from({ length: 200 }, (_, i) => String.fromCharCode(0x100 + i * 3) + "-" + String.fromCharCode(0x102 + i * 3)).join("");
  const words = "Alphabetic Lowercase Uppercase Modifier_Letter Other_Letter Decimal_Number Connector_Punctuation Format_Control";
  const tables = [ranges, ...Array.from({ length: 24 }, () => words)];
  const inspect = (values: string[], behavior = "") => {
    const content = values.map((value, i) => `const table${i} = ${JSON.stringify(value)};`).join("\n") + behavior;
    return scanExtractedPackage({ ...pkg, packageJson: { scripts: { prepare: "node build.js" } },
      files: [{ path: "parser.js", kind: "source", content, size: Buffer.byteLength(content) }] });
  };
  const passive = inspect(tables, '\nconst reference = "https://example.invalid/parser";');
  assert.equal(passive.decision, "warn");
  assert.equal(passive.findings.filter(f => f.type === "high_entropy_string").length, tables.length);
  const standalone = scanExtractedPackage({ ...pkg, files: [{ path: "data.js", kind: "source", content: `const ranges = ${JSON.stringify(ranges)};`, size: ranges.length }] });
  assert.equal(standalone.decision, "warn", "Table shape must not be treated as proof of safety");
  for (const behavior of ['\neval(table0);', '\natob(table0);', '\nfetch(table0);', '\nrequire("child_process").exec(table0);']) {
    assert.equal(inspect(tables, behavior).decision, "block", behavior);
  }
  const payload = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".repeat(12);
  const disguised = "one two three four five six seven eight " + payload;
  assert.equal(inspect(Array(6).fill(disguised)).decision, "block", "A few words must not hide a long encoded payload");
});
