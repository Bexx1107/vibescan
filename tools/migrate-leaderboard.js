'use strict';
/**
 * One-shot migration: data/history.json + data/reports/*.json → SQLite.
 *
 * Usage:
 *   node tools/migrate-leaderboard.js [--dry-run]
 *
 * Idempotent: running twice does not duplicate scans (it skips report ids that
 * are already present). Only derived fields are copied — never `findings[].evidence`.
 */

const fs = require('fs');
const path = require('path');
const db = require('../lib/db');

const DATA_DIR = path.join(__dirname, '..', 'data');
const REPORTS_DIR = path.join(DATA_DIR, 'reports');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');

const DRY = process.argv.includes('--dry-run');

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function main() {
  const history = readJson(HISTORY_FILE);
  if (!Array.isArray(history)) {
    console.error('No readable history.json at ' + HISTORY_FILE);
    process.exit(1);
  }

  const conn = db.open();
  const already = new Set(
    conn
      .prepare('SELECT report_id FROM scan')
      .all()
      .map((r) => r.report_id)
  );

  let imported = 0;
  let skipped = 0;
  let missing = 0;
  let notWeb = 0;
  const hosts = new Set();

  for (const entry of history) {
    if (!entry || !entry.id) continue;
    if (already.has(entry.id)) {
      skipped++;
      continue;
    }
    const report = readJson(path.join(REPORTS_DIR, entry.id + '.json'));
    if (!report) {
      missing++;
      continue;
    }
    const host = db.normaliseHost(report.finalUrl || report.target);
    if (!host) {
      notWeb++; // local://, file://, IP-only — internal scans, not leaderboard entries
      continue;
    }
    if (DRY) {
      hosts.add(host);
      imported++;
      continue;
    }
    const res = db.recordScan(report, { reportId: entry.id });
    hosts.add(res.host);
    imported++;
  }

  if (DRY) {
    console.log(
      `[dry-run] would import ${imported} scan(s), skip ${skipped} existing, ` +
        `${missing} missing report file(s), ${notWeb} non-web target(s), ` +
        `across ${hosts.size} site(s)`
    );
    return;
  }

  console.log(
    `imported ${imported} scan(s), skipped ${skipped} existing, ` +
      `${missing} missing report file(s), ${notWeb} non-web target(s) skipped`
  );
  console.log('db stats:', JSON.stringify(db.stats()));
  db.close();
}

main();
