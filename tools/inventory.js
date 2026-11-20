'use strict';
// Complete finding inventory across all lib modules.
//
// Two factory shapes exist:
//   mkFor('domain') => (id, severity, title, detail, fix, evidence)   // mkA11y mkPerf mkEu mkProbe mkSeo
//   local function mk(id, title, detail, fix, ev)                     // inside checkSeo()
// plus literal makeFinding({...}) objects.
//
// Output: TSV  id \t severity \t title \t detail \t fix \t file

const fs = require('fs');
const path = require('path');
const libDir = path.join(__dirname, '..', 'lib');

const norm = (s) => (s == null ? '' : s).replace(/\$\{[^}]*\}/g, 'N').replace(/\s+/g, ' ').trim();
const strip = (s) => (s == null ? '' : s).slice(1, -1);

const rows = new Map();
const add = (id, sev, title, detail, fix, file) => {
  if (!id || rows.has(id)) return;
  rows.set(id, { id, sev: sev || '', title: norm(strip(title)), detail: norm(strip(detail)), fix: norm(strip(fix)), file });
};

const LIT = '(`(?:[^`\\\\]|\\\\.)*`|\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*")';

for (const file of fs.readdirSync(libDir).filter((f) => f.endsWith('.js') && f !== 'queue.js')) {
  const src = fs.readFileSync(path.join(libDir, file), 'utf8');

  // factory mk*(id, severity, title, detail, fix, ev)
  const r1 = new RegExp(`\\bmk[A-Za-z]*\\(\\s*'([a-z0-9-]+)'\\s*,\\s*'([a-z]+)'\\s*,\\s*${LIT}\\s*,\\s*${LIT}\\s*,\\s*${LIT}`, 'g');
  let m;
  while ((m = r1.exec(src))) add(m[1], m[2], m[3], m[4], m[5], file);

  // local mk(id, title, detail, fix, ev)  — 4 string-ish args, no severity
  const r2 = new RegExp(`\\bmk\\(\\s*'([a-z0-9-]+)'\\s*,\\s*${LIT}\\s*,\\s*${LIT}\\s*,\\s*${LIT}`, 'g');
  while ((m = r2.exec(src))) add(m[1], 'low', m[2], m[3], m[4], file);

  // literal makeFinding({...})
  for (const mm of src.matchAll(/makeFinding\(\{([\s\S]{0,1500}?)\}\s*\)/g)) {
    const b = mm[1];
    const g = (re) => { const t = b.match(re); return t ? t[1] : ''; };
    const id = g(/id:\s*'([a-z0-9-]+)'/);
    if (!id) continue;
    add(
      id,
      g(/severity:\s*'([a-z]+)'/),
      g(new RegExp(`title:\\s*${LIT}`)),
      g(new RegExp(`detail:\\s*${LIT}`)),
      g(new RegExp(`fix:\\s*${LIT}`)),
      file
    );
  }
}

if (process.argv.includes('--json')) {
  console.log(JSON.stringify([...rows.values()], null, 1));
} else {
  for (const r of [...rows.values()].sort((a, b) => a.id.localeCompare(b.id))) {
    console.log([r.id, r.sev, r.title, r.detail, r.fix, r.file].join('\t'));
  }
  console.error('# ' + rows.size + ' findings');
}
