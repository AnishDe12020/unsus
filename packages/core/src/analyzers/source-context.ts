import * as acorn from "acorn";
import type { PackageFile } from "../types.js";

interface SourceContext {
  isCode: (offset: number) => boolean;
  strings: Array<{ value: string; start: number }>;
  unparsedOffset?: number;
}
const contexts = new WeakMap<PackageFile, SourceContext>();

/** Lexical context, not a complete data-flow or TypeScript analysis. */
export function sourceContext(file: PackageFile): SourceContext {
  const cached = contexts.get(file);
  if (cached) return cached;
  const ignored: Array<[number, number]> = [];
  const strings: SourceContext["strings"] = [];
  let lastTokenEnd = 0;
  const tokens = acorn.tokenizer(file.content ?? "", {
    ecmaVersion: "latest",
    allowHashBang: true,
    onComment: (_block, _text, start, end) => { ignored.push([start, end]); lastTokenEnd = Math.max(lastTokenEnd, end); }
  });
  let unparsedOffset: number | undefined;
  try {
    for (const token of tokens) {
      lastTokenEnd = token.end;
      if (["string", "regexp", "template"].includes(token.type.label)) ignored.push([token.start, token.end]);
      const value = "value" in token ? token.value : undefined;
      if (["string", "template"].includes(token.type.label) && typeof value === "string") strings.push({ value, start: token.start });
    }
  } catch {
    unparsedOffset = lastTokenEnd;
    // Unsupported syntax retains conservative pattern scanning for the unparsed tail.
  }
  ignored.sort((a, b) => a[0] - b[0]);
  const context: SourceContext = { strings, ...(unparsedOffset !== undefined ? { unparsedOffset } : {}), isCode: (offset: number) => {
    let low = 0, high = ignored.length - 1;
    while (low <= high) {
      const mid = (low + high) >>> 1;
      const range = ignored[mid]!;
      if (offset < range[0]) high = mid - 1;
      else if (offset >= range[1]) low = mid + 1;
      else return false;
    }
    return true;
  } };
  contexts.set(file, context);
  return context;
}
