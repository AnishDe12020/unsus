import type { Decision, RiskLevel, RiskPolicy } from "../types.js";

export const defaultPolicy: RiskPolicy = {
  allowLevels: ["safe", "low"],
  warnLevels: ["medium"],
  blockLevels: ["high", "critical"]
};

export function decisionFromPolicy(level: RiskLevel, policy: RiskPolicy = defaultPolicy): Decision {
  if (policy.failOn && riskLevelRank(level) >= riskLevelRank(policy.failOn)) {
    return "block";
  }

  if (policy.blockLevels.includes(level)) {
    return "block";
  }

  if (policy.warnLevels.includes(level)) {
    return "warn";
  }

  return "allow";
}

export function riskLevelRank(level: RiskLevel): number {
  return ["safe", "low", "medium", "high", "critical"].indexOf(level);
}
