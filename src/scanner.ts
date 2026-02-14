// src/scanner.ts
/**
 * Scanner Orchestrator
 * Main workflow: Extract package → Run analyzers → Calculate risk → Return results
 */

import { extractPackage, cleanupPackage, validatePackage, ExtractedPackage } from './extractors/package';

// ===== TYPE DEFINITIONS =====

export interface ScanOptions {
  verbose?: boolean;      // Show detailed progress
  timeout?: number;       // Timeout per analyzer (ms)
  skipLLM?: boolean;      // Skip LLM deobfuscation
}

export interface ScanResult {
  packageName: string;
  version: string;
  riskScore: number;          // 0-10
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  findings: Finding[];
  iocs: IOC[];
  summary: string;
  scanTime: number;           // Time taken in ms
}

export interface Finding {
  type: FindingType;
  severity: 'info' | 'warning' | 'danger' | 'critical';
  message: string;
  file: string;
  line: number;
  code: string;
}

export type FindingType = 
  | 'install-script'
  | 'eval'
  | 'exec'
  | 'network'
  | 'fs-access'
  | 'env-access'
  | 'obfuscation'
  | 'crypto-wallet'
  | 'dynamic-require'
  | 'vm-context'
  | 'base64-decode'
  | 'high-entropy';

export interface IOC {
  type: 'url' | 'domain' | 'ip' | 'wallet-eth' | 'wallet-btc' | 'wallet-sol' | 'env-var';
  value: string;
  context: string;
}

// ===== MAIN SCAN FUNCTION =====

/**
 * Scan a package for malware
 * @param target - Package name or local directory path
 * @param options - Scan options
 * @returns Scan results
 */
export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const startTime = Date.now();
  
  let pkg: ExtractedPackage | null = null;
  
  try {
    // Step 1: Extract package
    if (options.verbose) {
      console.log('\n🔍 Extracting package...');
    }
    pkg = await extractPackage(target);
    
    // Validate package
    const warnings = validatePackage(pkg);
    if (warnings.length > 0 && options.verbose) {
      console.warn('⚠️  Package warnings:', warnings);
    }
    
    // Step 2: Run all analyzers
    if (options.verbose) {
      console.log('🔬 Running analyzers...');
    }
    const findings = await runAnalyzers(pkg, options);
    
    // Step 3: Extract IOCs
    if (options.verbose) {
      console.log('🎯 Extracting IOCs...');
    }
    const iocs = extractIOCs(findings);
    
    // Step 4: Calculate risk score
    if (options.verbose) {
      console.log('📊 Calculating risk score...');
    }
    const riskScore = calculateRiskScore(findings);
    const riskLevel = getRiskLevel(riskScore);
    
    // Step 5: Generate summary
    const summary = generateSummary(pkg, findings, riskScore);
    
    const scanTime = Date.now() - startTime;
    
    return {
      packageName: pkg.packageJson.name,
      version: pkg.packageJson.version,
      riskScore,
      riskLevel,
      findings,
      iocs,
      summary,
      scanTime
    };
    
  } finally {
    // Always cleanup downloaded packages
    if (pkg) {
      cleanupPackage(pkg);
    }
  }
}

// ===== ANALYZER ORCHESTRATION =====

async function runAnalyzers(
  pkg: ExtractedPackage,
  options: ScanOptions
): Promise<Finding[]> {
  
  const allFindings: Finding[] = [];
  
  // Import analyzers dynamically (so they can be optional)
  const analyzers = await loadAnalyzers();
  
  // Run analyzers in parallel with timeout
  const timeout = options.timeout || 5000;
  const results = await Promise.allSettled(
    analyzers.map(async (analyzer) => {
      return withTimeout(
        analyzer.run(pkg.files, pkg.packageJson),
        timeout,
        analyzer.name
      );
    })
  );
  
  // Collect results
  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const analyzer = analyzers[i];
    
    if (result.status === 'fulfilled') {
      allFindings.push(...result.value);
      if (options.verbose) {
        console.log(`  ✓ ${analyzer.name}: ${result.value.length} findings`);
      }
    } else {
      console.warn(`  ✗ ${analyzer.name} failed: ${result.reason.message}`);
    }
  }
  
  return allFindings;
}

async function loadAnalyzers() {
  const analyzers: Array<{ name: string; run: Function }> = [];
  
  // Try to load each analyzer
  // If an analyzer doesn't exist, skip it gracefully
  
  try {
    const metadata = await import('./analyzers/metadata');
    analyzers.push({ name: 'metadata', run: metadata.analyzeMetadata });
  } catch {
    console.log('  ℹ️  metadata analyzer not available');
  }
  
  try {
    const ast = await import('./analyzers/ast');
    analyzers.push({ name: 'ast', run: ast.analyzeAST });
  } catch {
    console.log('  ℹ️  ast analyzer not available');
  }
  
  try {
    const entropy = await import('./analyzers/entropy');
    analyzers.push({ name: 'entropy', run: entropy.analyzeEntropy });
  } catch {
    console.log('  ℹ️  entropy analyzer not available');
  }
  
  try {
    const regex = await import('./analyzers/regex');
    analyzers.push({ name: 'regex', run: regex.analyzeRegex });
  } catch {
    console.log('  ℹ️  regex analyzer not available');
  }
  
  if (analyzers.length === 0) {
    throw new Error('No analyzers available! At least one analyzer is required.');
  }
  
  return analyzers;
}

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  name: string
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`${name} timeout`)), timeoutMs)
    )
  ]);
}

// ===== IOC EXTRACTION =====

function extractIOCs(findings: Finding[]): IOC[] {
  const iocs: IOC[] = [];
  const seen = new Set<string>();
  
  for (const finding of findings) {
    // Extract IOCs from finding code
    if (finding.type === 'crypto-wallet') {
      const ioc = extractIOCFromCode(finding.code, finding.file);
      if (ioc && !seen.has(ioc.value)) {
        iocs.push(ioc);
        seen.add(ioc.value);
      }
    }
    
    if (finding.type === 'network') {
      const urlMatch = finding.code.match(/https?:\/\/[^\s'"]+/);
      if (urlMatch) {
        const ioc: IOC = {
          type: 'url',
          value: urlMatch[0],
          context: `Found in ${finding.file}:${finding.line}`
        };
        if (!seen.has(ioc.value)) {
          iocs.push(ioc);
          seen.add(ioc.value);
        }
      }
    }
    
    if (finding.type === 'env-access') {
      const envMatch = finding.code.match(/process\.env\.([A-Z_][A-Z0-9_]*)/);
      if (envMatch) {
        const ioc: IOC = {
          type: 'env-var',
          value: envMatch[1],
          context: `Accessed in ${finding.file}:${finding.line}`
        };
        if (!seen.has(ioc.value)) {
          iocs.push(ioc);
          seen.add(ioc.value);
        }
      }
    }
  }
  
  return iocs;
}

function extractIOCFromCode(code: string, file: string): IOC | null {
  // Ethereum wallet
  const ethMatch = code.match(/0x[a-fA-F0-9]{40}/);
  if (ethMatch) {
    return {
      type: 'wallet-eth',
      value: ethMatch[0],
      context: `Found in ${file}`
    };
  }
  
  // Bitcoin wallet
  const btcMatch = code.match(/[13][a-km-zA-HJ-NP-Z1-9]{25,34}/);
  if (btcMatch) {
    return {
      type: 'wallet-btc',
      value: btcMatch[0],
      context: `Found in ${file}`
    };
  }
  
  return null;
}

// ===== RISK SCORING =====

function calculateRiskScore(findings: Finding[]): number {
  let score = 0;
  
  // Base score from severity
  for (const finding of findings) {
    switch (finding.severity) {
      case 'critical': score += 3.0; break;
      case 'danger': score += 2.0; break;
      case 'warning': score += 1.0; break;
      case 'info': score += 0.25; break;
    }
  }
  
  // Apply multipliers for compound risk patterns
  const hasInstallScript = findings.some(f => f.type === 'install-script');
  const hasNetworkCall = findings.some(f => f.type === 'network');
  const hasObfuscation = findings.some(f => f.type === 'obfuscation' || f.type === 'high-entropy');
  const hasExec = findings.some(f => f.type === 'exec' || f.type === 'eval');
  const hasEnvAccess = findings.some(f => f.type === 'env-access');
  
  // Multipliers
  if (hasInstallScript && hasNetworkCall) {
    score *= 1.5; // Classic exfiltration pattern
  }
  
  if (hasObfuscation && hasExec) {
    score *= 2.0; // Hiding execution = high risk
  }
  
  if (hasEnvAccess && hasNetworkCall) {
    score *= 1.5; // Credential theft pattern
  }
  
  // Cap at 10
  return Math.min(score, 10);
}

function getRiskLevel(score: number): 'safe' | 'low' | 'medium' | 'high' | 'critical' {
  if (score <= 1.0) return 'safe';
  if (score <= 3.0) return 'low';
  if (score <= 5.0) return 'medium';
  if (score <= 7.5) return 'high';
  return 'critical';
}

// ===== SUMMARY GENERATION =====

function generateSummary(
  pkg: ExtractedPackage,
  findings: Finding[],
  riskScore: number
): string {
  
  if (riskScore <= 1.0) {
    return `${pkg.packageJson.name} appears safe. No significant security concerns detected.`;
  }
  
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const dangerCount = findings.filter(f => f.severity === 'danger').length;
  
  if (riskScore >= 7.5) {
    return `⚠️ CRITICAL: ${pkg.packageJson.name} shows clear signs of malicious behavior. ` +
           `Detected ${criticalCount} critical issues. DO NOT USE.`;
  }
  
  if (riskScore >= 5.0) {
    return `⚠️ HIGH RISK: ${pkg.packageJson.name} contains suspicious patterns. ` +
           `Found ${criticalCount + dangerCount} serious issues. Investigate before use.`;
  }
  
  if (riskScore >= 3.0) {
    return `⚠️ MODERATE: ${pkg.packageJson.name} has some concerning patterns. ` +
           `Review findings carefully before using.`;
  }
  
  return `${pkg.packageJson.name} has minor concerns but likely safe for use.`;
}

// ===== UTILITIES =====

export function formatScanTime(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

// ===== STANDALONE TESTING =====

/**
 * Test the scanner
 * Run with: npx tsx src/scanner.ts
 */
async function test() {
  console.log('🧪 Testing Scanner...\n');
  
  // Test with a safe package
  try {
    console.log('Test 1: Scanning chalk (should be safe)');
    const result = await scan('chalk', { verbose: true });
    
    console.log('\n📊 Results:');
    console.log(`Package: ${result.packageName}@${result.version}`);
    console.log(`Risk Score: ${result.riskScore.toFixed(2)}/10`);
    console.log(`Risk Level: ${result.riskLevel}`);
    console.log(`Findings: ${result.findings.length}`);
    console.log(`IOCs: ${result.iocs.length}`);
    console.log(`Summary: ${result.summary}`);
    console.log(`Scan Time: ${formatScanTime(result.scanTime)}`);
    
  } catch (error) {
    console.error(`✗ Test failed: ${error.message}`);
    console.error(error.stack);
  }
}

// Run test if executed directly
if (require.main === module) {
  test().catch(console.error);
}