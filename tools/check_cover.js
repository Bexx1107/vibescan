'use strict';
// Coverage check: every finding id the engine can emit must resolve to a
// specific EXPLOIT walkthrough AND a specific EXPLAIN block (direct,
// suffix-stripped, or longest-prefix match), i.e. it must NOT fall through to
// the GENERIC_EXPLAIN / GENERIC_EXPLOIT fallbacks.
//
// The id inventory comes from tools/inventory.js, which understands every
// factory shape (mkFor domains, the local `mk()` in checkSeo, and literal
// makeFinding objects). The old inline regex only saw `id: 'x'` literals and
// therefore missed the entire SEO / accessibility / performance / compliance
// families — the exact findings that were rendering the vague generic card.
//
// Usage: node tools/check_cover.js            (human summary)
//        node tools/check_cover.js --json     (machine output)

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const inv = JSON.parse(
  execFileSync(process.execPath, [path.join(__dirname, 'inventory.js'), '--json'], { maxBuffer: 1 << 26 }).toString()
);
const src = fs.readFileSync(path.join(root, 'lib', 'scanner', 'knowledge.js'), 'utf8');

const slice = (a, b) => src.slice(src.indexOf(a), src.indexOf(b));
const exKeys = [...slice('const EXPLAIN = {', 'const EXPLOIT = {').matchAll(/\n  '([^']+)': \{/g)].map((m) => m[1]);
const xKeys = [...slice('const EXPLOIT = {', 'const GENERIC_EXPLOIT').matchAll(/\n  '([^']+)': \[/g)].map((m) => m[1]);

const resolveEx = (id) => {
  if (exKeys.includes(id)) return id;
  const s = id.replace(/-[^-]+$/, '');
  if (exKeys.includes(s)) return s;
  return exKeys.filter((k) => id === k || id.startsWith(k + '-') || id.startsWith(k)).sort((a, b) => b.length - a.length)[0] || null;
};
const resolveX = (id) => {
  if (xKeys.includes(id)) return id;
  const s = id.replace(/-[^-]+$/, '');
  if (xKeys.includes(s)) return s;
  return xKeys.filter((k) => id === k || id.startsWith(k)).sort((a, b) => b.length - a.length)[0] || null;
};

const missingExplain = inv.filter((f) => !resolveEx(f.id)).map((f) => f.id).sort();
const missingExploit = inv.filter((f) => !resolveX(f.id)).map((f) => f.id).sort();

if (process.argv.includes('--json')) {
  console.log(JSON.stringify({
    findings: inv.length,
    explainKeys: exKeys.length,
    exploitKeys: xKeys.length,
    missingExplain,
    missingExploit,
  }, null, 1));
  process.exit(0);
}

console.log('finding ids:', inv.length, '| EXPLAIN keys:', exKeys.length, '| EXPLOIT keys:', xKeys.length);
console.log('missing EXPLAIN coverage (' + missingExplain.length + '):');
console.log(missingExplain.length ? '  ' + missingExplain.join('\n  ') : '  (none)');
console.log('missing exploit coverage (' + missingExploit.length + '):');
console.log(missingExploit.length ? '  ' + missingExploit.join('\n  ') : '  (none)');

if (!missingExplain.length && !missingExploit.length) {
  console.log('\nOK — every finding has a specific explanation and exploit walkthrough.');
}
