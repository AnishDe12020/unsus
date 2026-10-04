import assert from "node:assert/strict";
import { test } from "node:test";

import { scanExtractedPackage } from "../scan.js";
import type { ExtractedPackage, Finding } from "../types.js";
import { formatSarifReport } from "./sarif.js";

function sample(source = 'eval("private source value");\n') {
  const pkg: ExtractedPackage = {
    identity: { name: "fixture", version: "1.0.0", requested: "/Users/private/package", registry: "https://private.example" },
    rootPath: "/Users/private/package", isLocal: true,
    packageJson: { scripts: { postinstall: "echo /Users/private/token" } },
    files: [{ path: "src/space # µ.js", size: source.length, kind: "source", content: source }]
  };
  return scanExtractedPackage(pkg);
}

test("SARIF reports rules, severity and real locations without embedding source or machine details", () => {
  const report = sample();
  const serialized = formatSarifReport(report);
  const sarif = JSON.parse(serialized);
  const run = sarif.runs[0];
  assert.equal(sarif.version, "2.1.0");
  assert.equal(run.tool.driver.name, "unsus");
  assert.equal(run.invocations[0].executionSuccessful, true);
  assert.equal(run.invocations[0].exitCode, report.decision === "block" ? 2 : report.decision === "warn" ? 1 : 0);
  assert.equal(run.properties.coverage.scope, "direct-package");
  assert.equal(run.invocations[0].properties.coverage.dependenciesAnalyzed, false);
  const result = run.results.find((item: { ruleId: string }) => item.ruleId === "unsus.eval_call");
  assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId);
  assert.equal(result.level, "error");
  assert.deepEqual(result.locations[0].physicalLocation, {
    artifactLocation: { uri: "src/space%20%23%20%C2%B5.js", uriBaseId: "%PACKAGE_ROOT%" },
    region: { startLine: 1 }
  });
  assert.match(result.partialFingerprints["unsus/matchedEvidence/v1"], /^[0-9a-f]{64}$/);
  const shifted = JSON.parse(formatSarifReport(sample('\n\n' + 'eval("private source value");\n'))).runs[0].results.find((item: { ruleId: string }) => item.ruleId === "unsus.eval_call");
  assert.equal(shifted.locations[0].physicalLocation.region.startLine, 3);
  assert.deepEqual(shifted.partialFingerprints, result.partialFingerprints);
  const lifecycle = run.results.find((item: { ruleId: string }) => item.ruleId === "unsus.lifecycle_script");
  assert.equal(lifecycle.locations[0].physicalLocation.region, undefined, "Metadata has no observed line");
  assert.doesNotMatch(serialized, /private source value|\/Users\/private|private\.example|echo |snippet|environmentVariables/);
});

test("SARIF omits unsafe paths and unavailable evidence, and makes incomplete coverage explicit", () => {
  const report = sample();
  const finding: Finding = { id: "fixture", type: "eval_call", category: "dynamic_code_execution", severity: "info", title: "private source", message: "/Users/private", confidence: 1 };
  const unsafe = ["/Users/private/a.js", "../outside.js", "a/../../outside.js", "C:\\Users\\private\\a.js", "file:///Users/private/a.js", "//server/a.js", "a\u0000b.js"];
  report.findings = unsafe.map(file => ({ ...finding, file, line: 1, code: "private code" }));
  report.findings.push({ ...finding, file: "package.json", line: 0 });
  report.coverage = { scope: "direct-package", complete: false, files: 1, textFilesAnalyzed: 0, omittedTextFiles: ["big # file.js", "../../private.js"], dependenciesAnalyzed: false, limitations: ["/Users/private"] };
  const serialized = formatSarifReport(report);
  const run = JSON.parse(serialized).runs[0];
  for (const result of run.results.slice(0, unsafe.length)) {
    assert.equal(result.locations, undefined);
    assert.equal(result.partialFingerprints, undefined);
    assert.equal(result.properties.locationOmitted, true);
  }
  assert.equal(run.results.at(-1).locations[0].physicalLocation.region, undefined);
  assert.equal(run.results.at(-1).partialFingerprints, undefined);
  assert.equal(run.results.at(-1).level, "note");
  assert.equal(run.properties.coverage.complete, false);
  assert.equal(run.properties.coverage.omittedTextFileCount, 2);
  assert.deepEqual(run.properties.coverage.omittedTextFiles, ["big%20%23%20file.js"]);
  assert.doesNotMatch(serialized, /Users|outside|private|snippet/);
  assert.throws(() => formatSarifReport({ ...report, sandbox: { enabled: false, timedOut: false, findings: [], timeline: [] } }), /static scans only/);
});
