import type { SandboxTimelineEvent } from "@unsus/core";

export function timelineEvent(type: string, message: string, evidence?: Record<string, unknown>): SandboxTimelineEvent {
  return {
    timeMs: 0,
    type,
    message,
    ...(evidence ? { evidence } : {})
  };
}
