// src/extractors/package.ts
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import pacote from 'pacote';
import * as tar from 'tar';

// ===== TYPE DEFINITIONS =====

export interface PackageJson {
  name: string;
  version: string;
  description?: string;
  main?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  keywords?: string[];
  author?: string | { name: string; email?: string };
  license?: string;
  [key: string]: any;
}

export interface FileEntry {
  path: string;
  content: string;
  size: number;
}

export interface ExtractedPackage {
  packageJson: PackageJson;
  files: FileEntry[];
  rootPath: string;
  isLocal: boolean;
}

// ===== CONFIGURATION =====

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const ALLOWED_EXTENSIONS = ['.js', '.mjs', '.cjs', '.json', '.ts'];
const IGNORED_DIRS = ['node_modules', '.git', 'test', 'tests', '__tests__', 'coverage', '.nyc_output'];

// ===== MAIN EXPORT =====

export async function extractPackage(target: string): Promise<ExtractedPackage> {
  if (isLocalDirectory(target)) {
    console.log(`📂 Loading local package: ${target}`);
    return await extractLocalPackage(target);
  } else {
    console.log(`📦 Downloading npm package: ${target}`);
    return await extractNpmPackage(target);
  }
}

// ===== LOCAL DIRECTORY EXTRACTION =====

function isLocalDirectory(target: string): boolean {
  try {
    const stat = fs.statSync(target);
    return stat.isDirectory();
  } catch {
    return false;
  }
}

async function extractLocalPackage(dirPath: string): Promise<ExtractedPackage> {
  const absolutePath = path.resolve(dirPath);
  const packageJson = readPackageJson(absolutePath);
  const files = readDirectoryFiles(absolutePath);
  
  return {
    packageJson,
    files,
    rootPath: absolutePath,
    isLocal: true
  };
}

function readPackageJson(dirPath: string): PackageJson {
  const pkgPath = path.join(dirPath, 'package.json');
  
  if (!fs.existsSync(pkgPath)) {
    throw new Error(`No package.json found in ${dirPath}`);
  }
  
  const content = fs.readFileSync(pkgPath, 'utf-8');
  return JSON.parse(content);
}

function readDirectoryFiles(dirPath: string): FileEntry[] {
  const files: FileEntry[] = [];
  
  function walkDir(currentPath: string, relativePath: string = '') {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      const relPath = path.join(relativePath, entry.name);
      
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.includes(entry.name)) {
          continue;
        }
        walkDir(fullPath, relPath);
        continue;
      }
      
      const ext = path.extname(entry.name);
      if (!ALLOWED_EXTENSIONS.includes(ext)) {
        continue;
      }
      
      const stats = fs.statSync(fullPath);
      if (stats.size > MAX_FILE_SIZE) {
        console.warn(`⚠️  Skipping large file: ${relPath} (${formatBytes(stats.size)})`);
        continue;
      }
      
      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        files.push({
          path: relPath,
          content,
          size: stats.size
        });
      } catch (error) {
        console.warn(`⚠️  Could not read file: ${relPath}`);
      }
    }
  }
  
  walkDir(dirPath);
  return files;
}

// ===== NPM PACKAGE EXTRACTION =====

async function extractNpmPackage(packageName: string): Promise<ExtractedPackage> {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'unsus-'));
  
  try {
    console.log(`   Downloading...`);
    
    // FIXED: Use pacote.extract instead of tarball
    const extractPath = path.join(tempDir, 'package');
    await pacote.extract(packageName, extractPath);
    
    console.log(`   ✓ Extracted`);
    
    const packageJson = readPackageJson(extractPath);
    const files = readDirectoryFiles(extractPath);
    
    console.log(`   ✓ Loaded ${files.length} files`);
    
    return {
      packageJson,
      files,
      rootPath: extractPath,
      isLocal: false
    };
    
  } catch (error: any) {
    cleanupTempDir(tempDir);
    throw new Error(`Failed to download package: ${error.message}`);
  }
}

// ===== CLEANUP =====

export function cleanupPackage(pkg: ExtractedPackage): void {
  if (!pkg.isLocal) {
    cleanupTempDir(path.dirname(pkg.rootPath));
  }
}

function cleanupTempDir(dirPath: string): void {
  try {
    if (fs.existsSync(dirPath)) {
      fs.rmSync(dirPath, { recursive: true, force: true });
    }
  } catch (error) {
    console.warn(`⚠️  Could not cleanup temp directory: ${dirPath}`);
  }
}

// ===== UTILITIES =====

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

export function validatePackage(pkg: ExtractedPackage): string[] {
  const warnings: string[] = [];
  
  if (!pkg.packageJson.name) {
    warnings.push('Package has no name');
  }
  
  if (!pkg.packageJson.version) {
    warnings.push('Package has no version');
  }
  
  if (pkg.files.length === 0) {
    warnings.push('Package has no scannable files');
  }
  
  return warnings;
}

// ===== STANDALONE TESTING =====

async function test() {
  console.log('🧪 Testing Package Extractor...\n');
  
  // Test 1: Local directory (if exists)
  try {
    console.log('Test 1: Local directory extraction');
    const localPkg = await extractPackage('./test-packages/level-1-obvious');
    console.log(`✓ Loaded: ${localPkg.packageJson.name}@${localPkg.packageJson.version}`);
    console.log(`✓ Files: ${localPkg.files.length}`);
    console.log();
  } catch (error: any) {
    console.log(`⚠️  Local test skipped: ${error.message}\n`);
  }
  
  // Test 2: npm package
  try {
    console.log('Test 2: npm package extraction');
    const npmPkg = await extractPackage('chalk');
    console.log(`✓ Loaded: ${npmPkg.packageJson.name}@${npmPkg.packageJson.version}`);
    console.log(`✓ Files: ${npmPkg.files.length}`);
    
    console.log('\nFirst 5 files:');
    npmPkg.files.slice(0, 5).forEach(f => {
      console.log(`  - ${f.path} (${formatBytes(f.size)})`);
    });
    
    cleanupPackage(npmPkg);
    console.log('\n✓ Cleanup successful');
    
  } catch (error: any) {
    console.error(`✗ npm test failed: ${error.message}`);
  }
}

if (require.main === module) {
  test().catch(console.error);
}