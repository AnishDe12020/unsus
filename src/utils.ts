
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);

  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    if (p > 0) e -= p * Math.log2(p);
  }
  return e;
}

export function truncate(s: string, n: number) {
  return s.length <= n ? s : s.slice(0, n - 3) + '...';
}

export function getLine(src: string, idx: number) {
  let ln = 1;
  for (let i = 0; i < idx && i < src.length; i++) {
    if (src[i] === '\n') ln++;
  }
  return ln;
}

// basic levenshtein, good enough for typosquat checks
export function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i]![0] = i;
  for (let j = 0; j <= n; j++) dp[0]![j] = j;

  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i]![j] = a[i-1] === b[j-1]
        ? dp[i-1]![j-1]!
        : 1 + Math.min(dp[i-1]![j]!, dp[i]![j-1]!, dp[i-1]![j-1]!);

  return dp[m]![n]!;
}
