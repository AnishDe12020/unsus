import * as acorn from "acorn";
import * as walk from "acorn-walk";
import type { Finding } from "../types.ts";

// \x68\x65\x6c\x6c\x6f or \u0072\u0065\u0071 — 3+ consecutive = sus
const HEX_CHAIN = /(?:\\x[0-9a-fA-F]{2}){3,}/;
const UNICODE_CHAIN = /(?:\\u[0-9a-fA-F]{4}){3,}/;
const UNICODE_BRACE = /(?:\\u\{[0-9a-fA-F]+\}){3,}/;

// env vars that are completely normal — downgrade to info
const BENIGN_ENV_PREFIXES = ['npm_config_', 'npm_package_', 'npm_lifecycle_'];
const BENIGN_ENV_VARS = new Set([
  'NODE_ENV', 'HOME', 'PATH', 'PWD', 'USER', 'SHELL', 'LANG', 'TERM', 'EDITOR',
  'CI', 'NETLIFY', 'HEROKU', 'DEBUG', 'VERBOSE', 'LOG_LEVEL', 'NODE_DEBUG',
  'NO_COLOR', 'FORCE_COLOR', 'REGISTRY_URL', 'HOSTNAME', 'PORT', 'HOST',
  'TMPDIR', 'TMP', 'TEMP', 'COLORTERM', 'COLUMNS', 'LINES',
]);
const BENIGN_ENV_GLOB_PREFIXES = ['GITHUB_', 'VERCEL_', 'NEXT_PUBLIC_', 'REACT_APP_'];

// env vars that indicate credential exfiltration — escalate to danger
const SENSITIVE_ENV_PATTERNS = [
  'SECRET', 'TOKEN', 'KEY', 'PASSWORD', 'PASSWD', 'CREDENTIAL', 'AUTH',
  'PRIVATE', 'API_KEY', 'APIKEY', 'ACCESS_KEY',
];
const SENSITIVE_ENV_PREFIXES = ['AWS_', 'AZURE_', 'GCP_', 'GOOGLE_CLOUD_'];
const SENSITIVE_ENV_VARS = new Set([
  'DATABASE_URL', 'REDIS_URL', 'MONGODB_URI', 'MONGO_URL',
  'SMTP_PASSWORD', 'SENDGRID_API_KEY', 'STRIPE_SECRET',
  'SSH_PRIVATE_KEY', 'GPG_PRIVATE_KEY',
]);

function envSeverity(name: string): 'info' | 'warning' | 'danger' {
  if (!name || name === '[computed]') return 'warning';
  const upper = name.toUpperCase();
  if (BENIGN_ENV_VARS.has(upper)) return 'info';
  if (BENIGN_ENV_PREFIXES.some(p => upper.startsWith(p.toUpperCase()))) return 'info';
  if (BENIGN_ENV_GLOB_PREFIXES.some(p => upper.startsWith(p))) return 'info';
  if (SENSITIVE_ENV_VARS.has(upper)) return 'danger';
  if (SENSITIVE_ENV_PREFIXES.some(p => upper.startsWith(p))) return 'danger';
  if (SENSITIVE_ENV_PATTERNS.some(p => upper.includes(p))) return 'danger';
  return 'warning';
}

export function analyzeAST(
  files: { path: string; content: string }[],
): Finding[] {
  const findings: Finding[] = [];
  // dedupe: if both foo.js and foo.min.js exist, skip the minified copy
  const bases = new Set(files.map(f => f.path.replace(/\.min\.(js|mjs|cjs)$/, '.$1')));
  for (const f of files) {
    const isMin = /\.min\.(js|mjs|cjs)$/.test(f.path);
    if (isMin && bases.has(f.path.replace(/\.min\./, '.'))) continue;
    scanEscapes(f.content, f.path, findings);
    const ast = parse(f.content, f.path, findings);
    if (ast) walkTree(ast, f.content, f.path, findings);
  }
  return findings;
}

function scanEscapes(src: string, file: string, out: Finding[]) {
  const lines = src.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const hm = HEX_CHAIN.exec(line);
    if (hm) {
      const decoded = hm[0].replace(/\\x([0-9a-fA-F]{2})/g, (_, h) =>
        String.fromCharCode(parseInt(h, 16)),
      );
      out.push({
        type: "hex-escape",
        severity: "danger",
        message: `Hex escape sequence → "${decoded}"`,
        file,
        line: i + 1,
        code: line
          .slice(Math.max(0, hm.index - 10), hm.index + hm[0].length + 10)
          .trim(),
      });
    }
    const um = UNICODE_CHAIN.exec(line);
    if (um) {
      const decoded = um[0].replace(/\\u([0-9a-fA-F]{4})/g, (_, h) =>
        String.fromCharCode(parseInt(h, 16)),
      );
      out.push({
        type: "hex-escape",
        severity: "danger",
        message: `Unicode escape sequence → "${decoded}"`,
        file,
        line: i + 1,
        code: line
          .slice(Math.max(0, um.index - 10), um.index + um[0].length + 10)
          .trim(),
      });
    }
    const bm = UNICODE_BRACE.exec(line);
    if (bm) {
      out.push({
        type: "hex-escape",
        severity: "danger",
        message: "Unicode brace escape sequence",
        file,
        line: i + 1,
        code: line
          .slice(Math.max(0, bm.index - 10), bm.index + bm[0].length + 10)
          .trim(),
      });
    }
  }
}

function parse(src: string, path: string, findings: Finding[]) {
  const opts = { ecmaVersion: "latest" as const, locations: true };
  try {
    return acorn.parse(src, { ...opts, sourceType: "module" });
  } catch {
    try {
      return acorn.parse(src, { ...opts, sourceType: "script" });
    } catch (e: any) {
      findings.push({
        type: "parse-error",
        severity: "info",
        message: `Failed to parse ${path}: ${e.message}`,
        file: path,
        line: 0,
        code: "",
      });
      return null;
    }
  }
}

function walkTree(ast: acorn.Node, src: string, file: string, out: Finding[]) {
  const snip = (n: any) => src.slice(n.start, Math.min(n.end, n.start + 120));
  const ln = (n: any) => n.loc?.start?.line ?? 0;

  // pre-pass: find lines with process.env.X to avoid double-counting bare process.env
  const envAccessLines = new Set<number>();
  walk.simple(ast, {
    MemberExpression(node: any) {
      if (
        node.object?.type === "MemberExpression" &&
        node.object.object?.name === "process" &&
        node.object.property?.name === "env"
      ) {
        envAccessLines.add(ln(node));
      }
    },
  });

  const cpNames = new Set<string>();
  walk.simple(ast, {
    VariableDeclarator(node: any) {
      if (
        node.init?.type === "CallExpression" &&
        node.init.callee?.name === "require" &&
        node.init.arguments?.[0]?.value === "child_process" &&
        node.id?.type === "Identifier"
      ) {
        cpNames.add(node.id.name);
      }
    },
  });

  walk.simple(ast, {
    CallExpression(node: any) {
      const callee = node.callee;
      const line = ln(node);
      const code = snip(node);

      // eval / Function
      if (callee.type === "Identifier") {
        if (callee.name === "eval") {
          out.push({
            type: "eval",
            severity: "critical",
            message: "eval() call",
            file,
            line,
            code,
          });
        }
        if (callee.name === "Function") {
          out.push({
            type: "eval",
            severity: "warning",
            message: "Function() constructor",
            file,
            line,
            code,
          });
        }

        // require()
        if (callee.name === "require" && node.arguments.length) {
          const arg = node.arguments[0];
          if (arg.type !== "Literal" || typeof arg.value !== "string") {
            out.push({
              type: "dynamic-require",
              severity: "danger",
              message: "Dynamic require() — computed argument",
              file,
              line,
              code,
            });
          } else if (arg.value === "child_process") {
            out.push({
              type: "exec",
              severity: "critical",
              message: "require('child_process')",
              file,
              line,
              code,
            });
          } else if (arg.value === "vm") {
            out.push({
              type: "vm-exec",
              severity: "critical",
              message: "require('vm')",
              file,
              line,
              code,
            });
          }
        }

        // bare exec calls (destructured from child_process)
        if (
          ["execSync", "spawnSync", "execFile", "execFileSync"].includes(
            callee.name,
          )
        ) {
          out.push({
            type: "exec",
            severity: "critical",
            message: `${callee.name}() call`,
            file,
            line,
            code,
          });
        }

        if (callee.name === "fetch") {
          out.push({
            type: "network",
            severity: "warning",
            message: "fetch() call",
            file,
            line,
            code,
          });
        }
      }

      // method calls: obj.method()
      if (callee.type === "MemberExpression") {
        const obj = callee.object;
        const prop = callee.property;

        // Buffer.from(x, 'base64')
        if (obj?.name === "Buffer" && prop?.name === "from") {
          const enc = node.arguments[1];
          if (enc?.type === "Literal" && enc.value === "base64")
            out.push({
              type: "base64-decode",
              severity: "danger",
              message: "Buffer.from(x, 'base64')",
              file,
              line,
              code,
            });
        }

        // String.fromCharCode
        if (obj?.name === "String" && prop?.name === "fromCharCode")
          out.push({
            type: "string-construction",
            severity: "warning",
            message: "String.fromCharCode()",
            file,
            line,
            code,
          });

        // http(s).request / .get
        if (
          obj?.type === "Identifier" &&
          (obj.name === "https" || obj.name === "http")
        )
          if (prop?.name === "request" || prop?.name === "get")
            out.push({
              type: "network",
              severity: "warning",
              message: `${obj.name}.${prop.name}()`,
              file,
              line,
              code,
            });

        if (prop?.type === "Identifier") {
          const isCP = obj?.type === "Identifier" && cpNames.has(obj.name);
          // execSync/spawnSync are unique to child_process, always flag
          if (["execSync", "spawnSync", "execFileSync"].includes(prop.name))
            out.push({
              type: "exec",
              severity: "critical",
              message: `obj.${prop.name}() — shell exec`,
              file,
              line,
              code,
            });
          // exec/spawn are ambiguous (regex.exec, EventEmitter.emit) — only flag on known cp vars
          if (["exec", "spawn", "execFile"].includes(prop.name) && isCP)
            out.push({
              type: "exec",
              severity: "critical",
              message: `${obj.name}.${prop.name}() — shell exec`,
              file,
              line,
              code,
            });
          if (
            prop.name === "runInNewContext" ||
            prop.name === "runInThisContext"
          )
            out.push({
              type: "vm-exec",
              severity: "critical",
              message: `vm.${prop.name}()`,
              file,
              line,
              code,
            });
        }

        // computed prop call — hiding method name?
        if (
          prop?.type !== "Identifier" &&
          prop?.type !== "Literal" &&
          node.arguments?.length
        ) {
          out.push({
            type: "dynamic-exec",
            severity: "warning",
            message: "Computed method call obj[x]()",
            file,
            line,
            code,
          });
        }
      }
    },

    NewExpression(node: any) {
      if (node.callee?.type === "Identifier" && node.callee.name === "Function")
        out.push({
          type: "eval",
          severity: "warning",
          message: "new Function()",
          file,
          line: ln(node),
          code: snip(node),
        });
    },

    MemberExpression(node: any) {
      const code = snip(node);
      const line = ln(node);

      // process.env.X or process.env[X]
      if (
        node.object?.type === "MemberExpression" &&
        node.object.object?.name === "process" &&
        node.object.property?.name === "env"
      ) {
        const varName = node.property?.name || "[computed]";
        const sev = envSeverity(varName);
        out.push({
          type: sev === "danger" ? "env-access-sensitive" : "env-access",
          severity: sev,
          message: `process.env.${varName}`,
          file,
          line,
          code,
        });
      }

      // bare process.env ref — only flag if not part of process.env.X on same line
      if (
        node.object?.name === "process" &&
        node.property?.name === "env" &&
        !envAccessLines.has(line)
      )
        out.push({
          type: "env-access-sensitive",
          severity: "warning",
          message: "process.env access (full env object)",
          file,
          line,
          code,
        });

      // fs operations
      if (node.object?.name === "fs" && node.property?.type === "Identifier") {
        if (
          [
            "readFileSync",
            "readFile",
            "readdirSync",
            "readdir",
            "existsSync",
            "writeFileSync",
            "writeFile",
            "appendFileSync",
            "unlinkSync",
            "rmdirSync",
            "rmSync",
          ].includes(node.property.name)
        )
          out.push({
            type: "fs-access",
            severity: "warning",
            message: `fs.${node.property.name}()`,
            file,
            line,
            code,
          });
      }

      // geo/locale sniffing — protestware pattern
      if (
        node.object?.name === "Intl" &&
        node.property?.name === "DateTimeFormat"
      )
        out.push({
          type: "geo-trigger",
          severity: "warning",
          message: "Intl.DateTimeFormat — locale/timezone sniffing",
          file,
          line,
          code,
        });
      if (
        node.object?.name === "navigator" &&
        node.property?.name === "language"
      )
        out.push({
          type: "geo-trigger",
          severity: "warning",
          message: "navigator.language — locale check",
          file,
          line,
          code,
        });
      if (
        node.object?.name === "navigator" &&
        node.property?.name === "languages"
      )
        out.push({
          type: "geo-trigger",
          severity: "warning",
          message: "navigator.languages — locale check",
          file,
          line,
          code,
        });
    },
  });

  // resolvedOptions().locale / .timeZone
  const geoRe = /resolvedOptions\(\)\s*\.\s*(locale|timeZone)/g;
  let gm;
  while ((gm = geoRe.exec(src)) !== null) {
    let ln = 1;
    for (let i = 0; i < gm.index; i++) if (src[i] === "\n") ln++;
    out.push({
      type: "geo-trigger",
      severity: "warning",
      message: `resolvedOptions().${gm[1]} — geo conditional`,
      file,
      line: ln,
      code: src.slice(gm.index, gm.index + 40),
    });
  }
}
