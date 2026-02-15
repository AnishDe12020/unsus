import { Database } from 'bun:sqlite';
import type { ScanResult } from '../types.ts';

const db = new Database('unsus.db');

db.run(`CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  packageName TEXT,
  version TEXT,
  riskScore REAL,
  riskLevel TEXT,
  result TEXT,
  timestamp INTEGER DEFAULT (unixepoch())
)`);

export function saveScan(result: ScanResult): number {
  const stmt = db.prepare(
    'INSERT INTO scans (packageName, version, riskScore, riskLevel, result) VALUES (?, ?, ?, ?, ?)'
  );
  const info = stmt.run(result.packageName, result.version, result.riskScore, result.riskLevel, JSON.stringify(result));
  return Number(info.lastInsertRowid);
}

export function getHistory(limit = 50) {
  return db.prepare(
    'SELECT id, packageName, version, riskScore, riskLevel, timestamp FROM scans ORDER BY id DESC LIMIT ?'
  ).all(limit);
}

export function getScan(id: number): ScanResult | null {
  const row: any = db.prepare('SELECT result FROM scans WHERE id = ?').get(id);
  if (!row) return null;
  return JSON.parse(row.result);
}
