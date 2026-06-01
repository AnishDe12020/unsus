import type { BehaviorCategory, Finding, FindingSeverity } from "../types.js";

export interface CreateFindingInput {
  category: BehaviorCategory;
  type: string;
  severity: FindingSeverity;
  title: string;
  message: string;
  file?: string;
  line?: number;
  code?: string;
  evidence?: Record<string, unknown>;
  confidence?: number;
}

export function createFinding(input: CreateFindingInput): Finding {
  return {
    id: `${input.category}.${input.type}.${input.file ?? "package"}.${input.line ?? 0}`,
    category: input.category,
    type: input.type,
    severity: input.severity,
    title: input.title,
    message: input.message,
    ...(input.file ? { file: input.file } : {}),
    ...(input.line ? { line: input.line } : {}),
    ...(input.code ? { code: input.code } : {}),
    ...(input.evidence ? { evidence: input.evidence } : {}),
    confidence: input.confidence ?? 0.8
  };
}

export function lineForOffset(content: string, offset: number): number {
  return content.slice(0, offset).split("\n").length;
}
