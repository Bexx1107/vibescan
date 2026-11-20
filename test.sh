#!/usr/bin/env bash
# VibeScan smoke test — asserts the scanner and SSRF guard behave.
set -uo pipefail
cd "$(dirname "$0")"
fail=0

check() { # desc, expected, actual
  if [[ "$2" == "$3" ]]; then echo "  ok   $1"; else echo "  FAIL $1 (expected '$2', got '$3')"; fail=1; fi
}

echo "== SSRF guard (should all be blocked) =="
for ip in 127.0.0.1 10.0.0.1 172.16.0.1 192.168.1.1 169.254.169.254 ::1 fe80::1 ::ffff:127.0.0.1; do
  out=$(node -e "require('./lib/scanner').assertPublicHost('$ip').then(()=>console.log('ALLOWED')).catch(()=>console.log('BLOCKED'))")
  check "$ip blocked" "BLOCKED" "$out"
done

echo "== Public IPs (should be allowed) =="
for ip in 8.8.8.8 1.1.1.1 172.32.0.1; do
  out=$(node -e "require('./lib/scanner').assertPublicHost('$ip').then(()=>console.log('ALLOWED')).catch(()=>console.log('BLOCKED'))")
  check "$ip allowed" "ALLOWED" "$out"
done

echo "== SSRF guard: hex / IPv4-mapped IPv6 private forms (regression) =="
# The old prefix-string check let every non-dotted spelling of loopback and
# cloud-metadata (169.254.169.254) through the guard.
for ip in '::ffff:7f00:1' '::ffff:a9fe:a9fe' '0:0:0:0:0:ffff:7f00:1' '::a9fe:a9fe' '64:ff9b::7f00:1' '2002:7f00:0001::' '::ffff:0a00:0001' '[::1]' '[::ffff:7f00:1]'; do
  out=$(node -e "require('./lib/scanner').assertPublicHost('$ip').then(()=>console.log('ALLOWED')).catch(()=>console.log('BLOCKED'))")
  check "$ip blocked (hex private form)" "BLOCKED" "$out"
done

echo "== SSRF guard: public IPv6 forms still allowed =="
for ip in '2001:4860:4860::8888' '2606:4700:4700::1111' '::ffff:8.8.8.8' '2002:0808:0808::'; do
  out=$(node -e "require('./lib/scanner').assertPublicHost('$ip').then(()=>console.log('ALLOWED')).catch(()=>console.log('BLOCKED'))")
  check "$ip allowed (public IPv6)" "ALLOWED" "$out"
done

echo "== Live scan of example.com =="
out=$(timeout 30 node lib/scanner.js https://example.com 2>&1 | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const r=JSON.parse(d);console.log(r.findings.length>0?'OK':'EMPTY')}catch(e){console.log('ERROR')}})")
check "example.com scan returns findings" "OK" "$out"

echo "== Explanation layer present on every finding =="
out=$(timeout 60 node -e "
require('./lib/scanner').scan('https://example.com').then(r=>{
  const ok = r.findings.every(f => f.whatItIs && f.whoCanAct && f.impact && f.worstCase);
  console.log(ok ? 'OK' : 'GENERIC'); process.exit(0);
}).catch(e=>{console.log('ERROR')});
" 2>&1 | tail -1)
check "every finding has what/who/impact/worst-case" "OK" "$out"

echo "== Exploit walkthrough present on every finding =="
out=$(timeout 60 node -e "
require('./lib/scanner').scan('https://example.com').then(r=>{
  const ok = r.findings.every(f => Array.isArray(f.exploitSteps) && f.exploitSteps.length >= 1);
  console.log(ok ? 'OK' : 'MISSING'); process.exit(0);
}).catch(e=>{console.log('ERROR')});
" 2>&1 | tail -1)
check "every finding has exploitSteps" "OK" "$out"

echo "== Coverage for every finding id (EXPLAIN + EXPLOIT) =="
out=$(node tools/check_cover.js | grep -q 'OK — every finding has a specific explanation' && echo OK || echo GAPS)
check "every finding id has a specific EXPLAIN + EXPLOIT entry" "OK" "$out"

echo "== No finding renders the generic fallback card =="
out=$(node tools/check_cover.js --json | node -e "
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
  const j=JSON.parse(d);
  console.log(j.missingExplain.length===0 ? 'OK' : 'GENERIC:'+j.missingExplain.join(','));
});")
check "no finding falls back to GENERIC_EXPLAIN" "OK" "$out"

echo "== Extended checks produce metadata =="
out=$(timeout 60 node -e "
require('./lib/scanner').scan('https://example.com').then(r=>{
  const hasDns = r.meta.dns && typeof r.meta.dns.spf === 'boolean';
  const hasTech = Array.isArray(r.meta.tech);
  const hasEndpoints = Array.isArray(r.meta.endpoints);
  console.log((hasDns && hasTech && hasEndpoints) ? 'OK' : 'MISSING'); process.exit(0);
}).catch(e=>{console.log('ERROR')});
" 2>&1 | tail -1)
check "dns + tech + endpoints metadata" "OK" "$out"

echo "== Redirect SSRF (should be blocked) =="
out=$(timeout 30 node -e "require('./lib/scanner').rawRequest('https://httpbin.org/redirect-to?url=http://169.254.169.254/').then(()=>console.log('ALLOWED')).catch(()=>console.log('BLOCKED'))" 2>&1)
check "redirect to metadata blocked" "BLOCKED" "$out"

echo "== Deep layer: link extraction stays same-origin =="
out=$(timeout 20 node -e "
const { extractLinks } = require('./lib/deep');
const links = extractLinks('<a href=\"/a\">a</a><a href=\"https://evil.com/x\">e</a><a href=\"/i.png\">i</a>', 'https://example.com/');
console.log(links.length === 1 && links[0] === 'https://example.com/a' ? 'OK' : 'BAD:' + JSON.stringify(links));
")
check "crawler drops external + asset links" "OK" "$out"

echo "== Deep layer: SPA detection heuristic =="
out=$(timeout 20 node -e "
const { looksLikeSpa } = require('./lib/deep');
const shell = looksLikeSpa('<html><body><div id=\"root\"></div><script>x</script></body></html>');
const rich = looksLikeSpa('<html><body>' + 'word '.repeat(400) + '</body></html>');
console.log(shell === true && rich === false ? 'OK' : 'BAD');
")
check "SPA shell detected, rich page not" "OK" "$out"

echo "== Deep layer: crawl returns page metadata =="
out=$(timeout 90 node -e "
require('./lib/scanner').scan('https://example.com', { deep: true, maxPages: 5, maxDepth: 1 }).then(r=>{
  const hasCrawl = r.meta.deep && r.meta.deep.crawl && typeof r.meta.deep.crawl.pagesScanned === 'number';
  console.log(hasCrawl ? 'OK' : 'MISSING'); process.exit(0);
}).catch(e=>{console.log('ERROR:' + e.message)});
" 2>&1 | tail -1)
check "deep scan produces crawl metadata" "OK" "$out"

echo "== Phase 1: persistent store saves + reloads a report =="
out=$(timeout 30 node -e "
const store = require('./lib/store');
const r = { target:'https://example.com', finalUrl:'https://example.com/', score:80, grade:'B', counts:{high:1}, findings:[{id:'x',severity:'high',domain:'security',title:'t'}], startedAt:new Date().toISOString(), durationMs:5, status:200 };
const meta = store.saveReport(r);
const back = store.getReport(meta.id);
const found = store.listHistory({ target:'https://example.com', limit:1 })[0];
console.log((back && back.score===80 && found && found.id===meta.id) ? 'OK' : 'BAD');
")
check "store round-trips a report" "OK" "$out"

echo "== Phase 1: diff detects added / removed / changed =="
out=$(timeout 20 node -e "
const { diffReports } = require('./lib/diff');
const prev = { score:70, grade:'C', findings:[
  {id:'a',severity:'high',domain:'security',title:'A',evidence:'e1'},
  {id:'b',severity:'low',domain:'seo',title:'B',evidence:'e2'} ] };
const next = { score:85, grade:'B', findings:[
  {id:'a',severity:'critical',domain:'security',title:'A',evidence:'e1'},
  {id:'c',severity:'medium',domain:'perf',title:'C',evidence:'e3'} ] };
const d = diffReports(prev,next);
const ok = d.added.length===1 && d.added[0].id==='c' && d.removed.length===1 && d.removed[0].id==='b' && d.severityChanged.length===1 && d.score.delta===15;
console.log(ok ? 'OK' : 'BAD:'+d.summary);
")
check "diff: +1 new, -1 fixed, 1 severity change, score +15" "OK" "$out"

echo "== Phase 1: exporters produce valid MD / HTML / SARIF =="
out=$(timeout 20 node -e "
const ex = require('./lib/export');
const r = { target:'https://example.com', finalUrl:'https://example.com/', score:80, grade:'B', status:200, startedAt:new Date().toISOString(), durationMs:5, counts:{high:1}, findings:[{id:'csp-missing',severity:'high',domain:'security',title:'CSP missing',fix:'Add CSP',whatItIs:'x',impact:'y',exploitSteps:['step 1'],evidence:'z'}] };
const md = ex.toMarkdown(r,null);
const html = ex.toHtml(r,null);
const sarif = JSON.parse(JSON.stringify(ex.toSarif(r)));
console.log((md.includes('csp-missing') && md.includes('step 1') && html.startsWith('<!doctype') && sarif.version==='2.1.0' && sarif.runs[0].results.length===1) ? 'OK' : 'BAD');
")
check "export: markdown + html + sarif 2.1.0" "OK" "$out"

echo "== Phase 1: job queue runs a scan and persists it =="
out=$(timeout 90 node -e "
const q = require('./lib/queue');
const job = q.enqueue('https://example.com', { deep:false, performance:false });
const t0 = Date.now();
(function poll(){
  const j = q.get(job.id);
  if (j.status==='done') { console.log(j.reportMeta && j.reportMeta.score>=0 ? 'OK' : 'NOMETA'); process.exit(0); }
  if (j.status==='error') { console.log('ERROR:'+j.error); process.exit(0); }
  if (Date.now()-t0 > 80000) { console.log('TIMEOUT'); process.exit(0); }
  setTimeout(poll, 300);
})();
")
check "async job completes with a persisted report" "OK" "$out"

echo "== Store: crafted report id cannot escape the reports dir =="
out=$(timeout 20 node -e "
const store = require('./lib/store');
const bad = ['../../etc/passwd', '..%2f..%2fpackage', 'a/../b', '', 'x'.repeat(200)];
const allNull = bad.every((id) => store.getReport(id) === null);
console.log(allNull ? 'OK' : 'LEAK');
")
check "store rejects path-traversal / oversized ids" "OK" "$out"

echo "== Server: malformed percent-encoding returns 4xx and does not crash =="
PORT=4299 HOST=127.0.0.1 node server.js >/dev/null 2>&1 &
SRV=$!
sleep 1.2
code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 'http://127.0.0.1:4299/api/report/%E0%A4%A' 2>/dev/null || echo 000)
alive=$(curl -s -o /dev/null -w '%{http_code}' -m 5 'http://127.0.0.1:4299/api/health' 2>/dev/null || echo 000)
kill $SRV 2>/dev/null
check "malformed id answered with 4xx" "400" "$code"
check "server survives malformed id (still serving)" "200" "$alive"

echo "== Scoring v2: good domains are not sunk by low/info volume =="
out=$(timeout 90 node -e "
require('./lib/scanner').scan('https://example.com', { deep: false, performance: false }).then(r=>{
  const allInfoLow = r.findings.every(f => f.severity === 'info' || f.severity === 'low');
  const ok = typeof r.score === 'number' && r.score > 0
    && typeof r.domainAverage === 'number' && typeof r.scoreCeiling === 'number'
    && (!allInfoLow || r.score >= 80);
  console.log(ok ? 'OK' : 'BAD:' + r.score);
}).catch(e => console.log('ERROR:' + e.message));
" 2>&1 | tail -1)
check "overall score is domain-aware and not clamped to 0" "OK" "$out"

echo "== A11y: label detection is per-field, not page-wide =="
out=$(timeout 20 node -e "
const a11y = require('./lib/a11y');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const page = (body) => '<html lang=\"en\"><head><title>T</title></head><body><main><h1>H</h1>' + body + '</main></body></html>';
// One field properly labelled, one genuinely unlabelled -> must flag the latter.
const a = a11y.checkA11yStatic(page('<label for=\"n\">Name</label><input id=\"n\"><input id=\"e\" type=\"email\">'), [], {}, mk);
const found = a.some((f) => f.id === 'a11y-label');
// Both wrapped in <label> (and one not explicitly closed) -> must NOT flag.
const b = a11y.checkA11yStatic(page('<label>Name <input id=\"a\"></label><label>Email <input id=\"b\"></main>'), [], {}, mk);
const clean = !b.some((f) => f.id === 'a11y-label');
console.log(found && clean ? 'OK' : 'BAD:' + found + '/' + clean);
")
check "per-field label detection (flags unlabelled, spares wrapped)" "OK" "$out"

echo "== A11y: label 'for' target is matched exactly (no prefix false-negative) =="
out=$(timeout 20 node -e "
const a11y = require('./lib/a11y');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const page = (body) => '<html lang=\"en\"><head><title>T</title></head><body><main><h1>H</h1>' + body + '</main></body></html>';
const flag = (b) => a11y.checkA11yStatic(page(b), [], {}, mk).some((f) => f.id === 'a11y-label');
// id=1 must NOT be considered labelled by an unrelated for=12 / for=1abc.
const prefixesFlagged = flag('<label for=\"12\">Other</label><input id=\"1\" type=\"text\">')
  && flag('<label for=\"1abc\">Other</label><input id=\"1\" type=\"text\">');
// Exact matches (double / single / unquoted) must still count as labelled.
const exactClean = !flag('<label for=\"1\">N</label><input id=\"1\" type=\"text\">')
  && !flag('<label for=\\'1\\'>N</label><input id=\"1\" type=\"text\">')
  && !flag('<label for=1 >N</label><input id=\"1\" type=\"text\">');
console.log(prefixesFlagged && exactClean ? 'OK' : 'BAD');
")
check "label for= is anchored (prefix ids not mislabelled)" "OK" "$out"

echo "== probes: error-verbosity signatures are valid regexes (no dead .test ternary) =="
out=$(timeout 20 node -e "
const src = require('fs').readFileSync('./lib/probes.js', 'utf8');
console.log(/\.test\s*\?/.test(src) ? 'DEAD-TERNARY' : 'OK');
")
check "no broken '.test ?' ternary in probes.js" "OK" "$out"

echo "== robots.txt: consecutive User-agent lines share one rule group =="
out=$(timeout 20 node -e "
const seo = require('./lib/seo');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const robots = { status: 200, body: 'User-agent: GPTBot\nUser-agent: ClaudeBot\nUser-agent: CCBot\nDisallow: /\n\nUser-agent: *\nDisallow: /admin\n' };
const meta = {};
seo.checkAiCrawlerPolicy('<html></html>', 'https://x.test', [], meta, mk, { robots });
const blocked = meta.seo.aiCrawlers.blocked;
const ok = blocked.includes('GPTBot') && blocked.includes('ClaudeBot') && blocked.includes('CCBot');
console.log(ok ? 'OK' : 'BAD:' + blocked.join('|'));
")
check "shared User-agent group is parsed as blocked" "OK" "$out"

echo "== A11y: controls without an id must not crash the static pass =="
out=$(timeout 20 node -e "
const a11y = require('./lib/a11y');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const page = (body) => '<html lang=\"en\"><head><title>T</title></head><body><main><h1>H</h1>' + body + '</main></body></html>';
// A plain <input> with no id (extremely common) used to make id.replace() throw,
// which the scanner swallowed via safeRun -> EVERY static a11y check skipped.
let out;
try {
  out = a11y.checkA11yStatic(page('<form><input type=\"text\" placeholder=\"Name\"><select><option>x</option></select></form>'), [], {}, mk);
} catch (e) { console.log('THREW:' + e.message); process.exit(0); }
const flagged = out.some((f) => f.id === 'a11y-label');
console.log(flagged ? 'OK' : 'BAD:no-flag');
")
check "id-less controls do not crash and are still flagged" "OK" "$out"

echo "== robots.txt: wildcard 'User-agent: * / Disallow: /' blocks AI crawlers =="
out=$(timeout 20 node -e "
const seo = require('./lib/seo');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const meta = {};
seo.checkAiCrawlerPolicy('<html></html>', 'https://x.test', [], meta, mk, { robots: { status: 200, body: 'User-agent: *\nDisallow: /\n' } });
const c = meta.seo.aiCrawlers;
// A blanket disallow blocks every bot, including the AI crawlers — the old code
// ignored the '*' group and reported them all as 'unlisted -> allowed'.
const ok = c.blocked.length >= 10 && c.allowed.length === 0;
console.log(ok ? 'OK' : 'BAD:blocked=' + c.blocked.length + ',allowed=' + c.allowed.length);
")
check "wildcard disallow blocks all AI crawlers" "OK" "$out"

echo "== robots.txt: an unrelated '*' group does NOT falsely block named bots =="
out=$(timeout 20 node -e "
const seo = require('./lib/seo');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const meta = {};
seo.checkAiCrawlerPolicy('<html></html>', 'https://x.test', [], meta, mk, { robots: { status: 200, body: 'User-agent: *\nDisallow: /admin\n' } });
const c = meta.seo.aiCrawlers;
const ok = c.blocked.length === 0 && c.allowed.length > 0;
console.log(ok ? 'OK' : 'BAD:blocked=' + c.blocked.join('|'));
")
check "partial wildcard rules do not over-block" "OK" "$out"

echo "== CWV: a perfect CLS/TBT of 0 is 'good', not 'n/a' =="
out=$(timeout 20 node -e "
const seo = require('./lib/seo');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const meta = {};
// measured flags prove the observers registered; 0 is then the best-case value.
seo.checkCwv({ lcp: 1200, cls: 0, tbt: 0, ttfb: 300, measured: { lcp: true, cls: true, tbt: true } }, [], meta, mk);
const v = meta.performance.verdicts;
console.log(v.cls === 'good' && v.tbt === 'good' ? 'OK' : 'BAD:' + JSON.stringify(v));
")
check "zero CLS/TBT reported good when measured" "OK" "$out"

echo "== CWV: an all-zero (unmeasured) reading stays 'n/a' =="
out=$(timeout 20 node -e "
const seo = require('./lib/seo');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const meta = {};
seo.checkCwv({ lcp: 0, cls: 0, tbt: 0, ttfb: 0 }, [], meta, mk);
const v = meta.performance.verdicts;
console.log(v.cls === 'n/a' && v.tbt === 'n/a' ? 'OK' : 'BAD:' + JSON.stringify(v));
")
check "unmeasured zeros stay n/a" "OK" "$out"

echo "== llms.txt is fetched and reported when present (regression) =="
# Bug: scanner fetched robots/sitemap/security.txt but never llms.txt, so
# peripherals.llms was always undefined and seo-llms-txt fired on EVERY site.
out=$(node -e "
const seo = require('./lib/seo');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const f = []; const meta = {};
seo.checkJsonLd('<html><script type=\"application/ld+json\">{\"@type\":\"Organization\"}</script></html>', 'https://x.test', f, meta, mk, { llms: { status: 200, body: '# X' } });
console.log(f.some(x => x.id === 'seo-llms-txt') ? 'FALSEPOS' : (meta.seo.llmsTxt ? 'OK' : 'NOTFLAGGED'));
")
check "served /llms.txt is not reported missing" "OK" "$out"

echo "== llms.txt still reported when genuinely absent (regression) =="
out=$(node -e "
const seo = require('./lib/seo');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const f = []; const meta = {};
seo.checkJsonLd('<html></html>', 'https://x.test', f, meta, mk, { llms: { status: 404 } });
console.log(f.some(x => x.id === 'seo-llms-txt') ? 'OK' : 'MISSED');
")
check "missing /llms.txt is still reported" "OK" "$out"

echo "== in-page fragment links are not 'links used as buttons' (regression) =="
# Bug: href=\"#section\" (tables of contents, skip-links) matched the same regex
# as href=\"#\" and were reported as WCAG 4.1.2 pseudo-buttons.
out=$(node -e "
const a11y = require('./lib/a11y');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const html = '<main><a href=\"#cenik\">Pricing</a><a href=\"#faq\">FAQ</a><a href=\"#orodje\">Tool</a><a href=\"#primerjava\">Compare</a></main>';
const meta = {};
const f = a11y.checkA11yStatic(html, [], meta, mk);
console.log(f.some(x => x.id === 'a11y-button-semantics') ? 'FALSEPOS' : 'OK');
")
check "fragment-only nav links are not flagged" "OK" "$out"

echo "== real javascript: pseudo-buttons ARE still flagged (regression) =="
out=$(node -e "
const a11y = require('./lib/a11y');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const html = '<main><a href=\"javascript:void(0)\">A</a><a href=\"#\">B</a><a href=\"\">C</a></main>';
const meta = {};
const f = a11y.checkA11yStatic(html, [], meta, mk);
console.log(f.some(x => x.id === 'a11y-button-semantics') ? 'OK' : 'MISSED');
")
check "javascript:/empty/bare-# anchors are flagged" "OK" "$out"

echo "== prose mentioning 'drift'/'intercom' is not a chat widget (regression) =="
# Bug: the EU AI Act check matched bare words in body copy, so a pricing tier
# called \"Rank Drift\" produced a false AI Act disclosure finding.
out=$(node -e "
const eu = require('./lib/eu');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const html = '<main><h2>Rank Drift</h2><p>Our drift detection compares your position over time.</p></main>';
const meta = {};
const f = eu.checkEuCompliance(html, { headers: {}, url: 'https://x.test' }, [], meta, {}, mk);
console.log(f.some(x => x.id === 'eu-ai-act-disclosure') ? 'FALSEPOS' : 'OK');
")
check "the word 'drift' in copy does not trigger AI Act" "OK" "$out"

echo "== a real chat widget IS still detected (regression) =="
out=$(node -e "
const eu = require('./lib/eu');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const html = '<script src=\"https://widget.intercom.io/widget/abc\"></script>';
const meta = {};
const f = eu.checkEuCompliance(html, { headers: {}, url: 'https://x.test' }, [], meta, {}, mk);
console.log(f.some(x => x.id === 'eu-ai-act-disclosure') ? 'OK' : 'MISSED');
")
check "intercom widget host is detected" "OK" "$out"

echo "== a SaaS page with prices but no cart is not a DSA shop (regression) =="
out=$(node -e "
const eu = require('./lib/eu');
const mk = (id, sev, title) => ({ id, severity: sev, title });
const html = '<main><h2>Pricing</h2><div>Pro 79 EUR</div><script type=\"application/ld+json\">{\"@type\":\"Offer\",\"price\":\"79.00\"}</script></main>';
const meta = {};
const f = eu.checkEuCompliance(html, { headers: {}, url: 'https://x.test' }, [], meta, {}, mk);
console.log(f.some(x => x.id === 'eu-dsa-trader-info') ? 'FALSEPOS' : 'OK');
")
check "prices without a cart do not trigger DSA trader info" "OK" "$out"

echo "== onclick inside JSON-LD is not deprecated inline markup (regression) =="
out=$(node -e "
const s = require('./lib/scanner');
const findings = []; const meta = {};
s.checkQuality('<html><body><div id=\"root\"></div><script type=\"application/ld+json\">{\"description\":\"onclick= handler\"}</script></body></html>', { headers: {} }, findings, meta);
const dep = findings.find(x => x.id === 'deprecated');
console.log(dep && /onclick/i.test(JSON.stringify(dep)) ? 'FALSEPOS' : 'OK');
" 2>&1 | tail -1)
check "onclick in JSON-LD is not flagged as deprecated" "OK" "$out"

echo "== Auth: non-loopback bind gates /api/* and advertises it via /api/health =="
# Regression guard for the access-token UX fix: the UI relies on /api/health
# reporting `auth:true` (so it can prompt up front) and on everything else
# under /api/* refusing anonymous calls. Also asserts the token is actually
# accepted, so a typo in the gate can't pass by blocking everyone.
AUTH_PORT=4298
# VIBESCAN_ALLOW_INSECURE=0 is explicit: this checkout's `.env` intentionally
# disables auth for the local single-operator instance, and server.js only fills
# in env vars that are unset. Without this the test would inherit that opt-out
# and measure the local policy instead of the gate it claims to test.
PORT=$AUTH_PORT HOST=0.0.0.0 VIBESCAN_TOKEN=testtoken123 VIBESCAN_ALLOW_INSECURE=0 node server.js >/dev/null 2>&1 &
ASRV=$!
sleep 1.2
hcode=$(curl -s -m 5 "http://127.0.0.1:$AUTH_PORT/api/health" || echo '{}')
h_auth=$(node -e "try{process.stdout.write(String(JSON.parse(process.argv[1]).auth))}catch(e){process.stdout.write('parse-error')}" "$hcode")
hist_anon=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$AUTH_PORT/api/history" 2>/dev/null || echo 000)
hist_bad=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -H 'Authorization: Bearer wrong' "http://127.0.0.1:$AUTH_PORT/api/history" 2>/dev/null || echo 000)
hist_ok=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -H 'Authorization: Bearer testtoken123' "http://127.0.0.1:$AUTH_PORT/api/history?limit=1" 2>/dev/null || echo 000)
# /api/health must stay reachable anonymously (the UI needs it to detect auth).
kill $ASRV 2>/dev/null
check "health advertises auth:true when token set" "true" "$h_auth"
check "anonymous /api/history is refused" "401" "$hist_anon"
check "wrong token is refused" "401" "$hist_bad"
check "correct token is accepted" "200" "$hist_ok"

echo "== Auth: loopback bind needs no token (default) =="
PORT=4297 HOST=127.0.0.1 VIBESCAN_TOKEN= node server.js >/dev/null 2>&1 &
LSRV=$!
sleep 1.2
l_auth=$(curl -s -m 5 "http://127.0.0.1:4297/api/health" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{process.stdout.write(String(JSON.parse(s).auth))}catch(e){process.stdout.write('parse-error')}})")
l_hist=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:4297/api/history?limit=1" 2>/dev/null || echo 000)
kill $LSRV 2>/dev/null
check "loopback health advertises auth:false" "false" "$l_auth"
check "loopback /api/history is open" "200" "$l_hist"

echo
[[ $fail -eq 0 ]] && echo "ALL PASS" || echo "SOME TESTS FAILED"
exit $fail
