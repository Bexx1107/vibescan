'use strict';
/**
 * Integration tests against local ephemeral HTTP fixture servers plus
 * regression checks for WAF-bypass header isolation, tech detection accuracy,
 * leaderboard publicReport shaping, and SQLite scan integrity preservation.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const zlib = require('zlib');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const scanner = require('../lib/scanner');
const deep = require('../lib/deep');
const integrity = require('../lib/integrity');
const leaderboard = require('../lib/leaderboard');
const {
  runPageChecks,
  scoreByDomain,
  penaltyToScore,
  MAX_LOW_PENALTY_PER_DOMAIN,
} = require('../lib/scanner/scoring');
const {
  checkSecurityHeaders,
  checkModernHeaders,
  checkCookies,
  checkCors,
} = require('../lib/scanner/headers');
const { checkQuality } = require('../lib/scanner/content');

const { scan, assertPublicHost, detectTech, _TEST_ALLOW_LOOPBACK } = scanner;

const servers = [];

function startFixtureServer(handler) {
  return new Promise((resolve, reject) => {
    const srv = http.createServer(handler);
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      servers.push(srv);
      const addr = srv.address();
      resolve({ server: srv, port: addr.port, origin: `http://127.0.0.1:${addr.port}` });
    });
  });
}

test.after(async () => {
  await Promise.all(
    servers.map(
      (srv) =>
        new Promise((resolve) => {
          srv.close(() => resolve());
        })
    )
  );
});

function buildGoodSiteHandler(originRef) {
  return (req, res) => {
    const reqUrl = new URL(req.url, originRef.origin);
    const p = reqUrl.pathname;
    const baseHeaders = {
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cache-Control': 'public, max-age=3600',
    };

    const sendHtml = (titleText, h1Text, mainCopy) => {
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${titleText}</title>
  <meta name="description" content="Independent hardened portal delivering verified technical documentation, transparent compliance disclosures, and strict browser security controls for visitors." />
  <link rel="canonical" href="${originRef.origin}${p}" />
  <meta property="og:title" content="${titleText}" />
  <meta property="og:description" content="Hardened portal with structured compliance and metadata." />
  <meta property="og:image" content="${originRef.origin}/hero.webp" />
  <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"Hardened Fixture","url":"${originRef.origin}/"}</script>
  <script defer src="/app.js"></script>
</head>
<body>
  <header>
    <nav aria-label="Primary">
      <a href="/">Home</a>
      <a href="/about">About</a>
      <a href="/privacy">Privacy Policy</a>
    </nav>
  </header>
  <main>
    <h1>${h1Text}</h1>
    <p>${mainCopy}</p>
    <img src="/hero.webp" alt="Hardened portal architecture diagram" width="600" height="400" />
  </main>
  <footer>
    <a href="/privacy">Privacy Policy</a>
    <a href="/about">Legal Notice</a>
    <a href="/privacy">Imprint</a>
  </footer>
</body>
</html>`;
      const gz = zlib.gzipSync(Buffer.from(html, 'utf8'));
      res.writeHead(200, {
        ...baseHeaders,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Encoding': 'gzip',
      });
      if (req.method === 'HEAD') return res.end();
      return res.end(gz);
    };

    if (p === '/') {
      return sendHtml(
        'Hardened Security & Compliance Portal Overview | Fixture',
        'Hardened Security & Compliance Portal',
        'This hardened reference application demonstrates complete HTTP response security headers, clean semantic HTML structure, descriptive image alternatives, zero unconsented tracking scripts, and crawlable technical metadata across multiple pages for deterministic integration testing.'
      );
    }
    if (p === '/about') {
      return sendHtml(
        'About the Hardened Reference Architecture | Fixture Site',
        'About Architecture',
        'Technical background covering content security policy rules, subresource discipline, accessible semantic landmarks, and transparent legal ownership notices.'
      );
    }
    if (p === '/privacy') {
      return sendHtml(
        'Privacy Policy and Data Protection Notice | Fixture Site',
        'Privacy Policy',
        'Personal data is processed minimally without advertising trackers or unauthorized profiling scripts.'
      );
    }
    if (p === '/hero.webp') {
      res.writeHead(200, { ...baseHeaders, 'Content-Type': 'image/webp' });
      return res.end(Buffer.from('RIFF\x18\x00\x00\x00WEBPVP8 \x0c\x00\x00\x00\x00\x00\x00\x00', 'binary'));
    }
    if (p === '/app.js') {
      res.writeHead(200, { ...baseHeaders, 'Content-Type': 'application/javascript; charset=utf-8' });
      return res.end('document.documentElement.dataset.ready = "1";\n');
    }
    if (p === '/robots.txt') {
      res.writeHead(200, { ...baseHeaders, 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(`User-agent: *\nAllow: /\nSitemap: ${originRef.origin}/sitemap.xml\n`);
    }
    if (p === '/sitemap.xml') {
      res.writeHead(200, { ...baseHeaders, 'Content-Type': 'application/xml; charset=utf-8' });
      return res.end(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${originRef.origin}/</loc></url><url><loc>${originRef.origin}/about</loc></url></urlset>`);
    }
    if (p === '/.well-known/security.txt') {
      res.writeHead(200, { ...baseHeaders, 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Contact: mailto:security@example.test\nExpires: 2027-12-31T23:59:59Z\n');
    }
    if (p === '/llms.txt') {
      res.writeHead(200, { ...baseHeaders, 'Content-Type': 'text/markdown; charset=utf-8' });
      return res.end('# Hardened Fixture\n> Reference target for integration verification.\n');
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  };
}

function buildBadSiteHandler() {
  // Construct synthetic credential strings dynamically so static repo secret scanners do not false-alert.
  const fakeAws = 'AKIA' + '1234567890ABCDEF';
  const fakeStripe = 'sk_' + 'live_' + '0123456789abcdef0123456789ab';
  const fakeGh = 'ghp_' + 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8';

  return (req, res) => {
    const p = req.url.split('?')[0];
    if (p === '/') {
      const html = `<html>
<head>
  <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
  <script src="https://www.googletagmanager.com/gtag/js?id=G-TEST12345"></script>
  <script src="/bundle.js"></script>
</head>
<body>
  <div class="hero">Welcome to insecure app</div>
  <img src="/banner.png">
  <a href="/missing-page">Broken Link</a>
  <script>
    const awsKey = "${fakeAws}";
    const stripeKey = "${fakeStripe}";
  </script>
</body>
</html>`;
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        Server: 'Apache/2.4.49',
        'X-Powered-By': 'PHP/7.4.3',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
        'Set-Cookie': 'sid=deadbeef; Path=/',
      });
      return res.end(html);
    }
    if (p === '/bundle.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return res.end(`window.__GH__ = "${fakeGh}";\nfetch('/api/v1/admin/tokens');\n`);
    }
    if (p === '/.env') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('DB_PASSWORD=supersecretpassword\nJWT_SECRET=dontcommitme\n');
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Missing');
  };
}

function buildWafSiteHandler() {
  return (req, res) => {
    const p = req.url.split('?')[0];
    if (p === '/robots.txt') {
      res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
      });
      return res.end('User-agent: *\nDisallow:\n');
    }
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=UTF-8',
      Server: 'cloudflare',
      'cf-mitigated': 'challenge',
      'cf-ray': 'fixture001-LJU',
      'content-security-policy':
        "default-src 'none'; script-src 'nonce-abc123' 'unsafe-eval' https://challenges.cloudflare.com;",
    });
    res.end(`<!DOCTYPE html><html lang="en"><head><title>Just a moment...</title></head><body><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script><p>Checking your browser before accessing the site.</p></body></html>`);
  };
}

test('SSRF guard blocks loopback by default and rejects private targets even with loopback test symbol', async () => {
  const ref = { origin: '' };
  const fx = await startFixtureServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  });
  ref.origin = fx.origin;

  await assert.rejects(
    () => scan(fx.origin, { deep: false, skipActive: true }),
    /SSRF blocked/i
  );

  // Plain JSON keys / property lookalikes cannot bypass the non-serializable Symbol.
  await assert.rejects(
    () => scan(fx.origin, { deep: false, skipActive: true, allowLoopback: true, _TEST_ALLOW_LOOPBACK: true }),
    /SSRF blocked/i
  );

  await assert.rejects(
    () => assertPublicHost('169.254.169.254', { [_TEST_ALLOW_LOOPBACK]: true }),
    /SSRF blocked/i
  );
  await assert.rejects(
    () => assertPublicHost('10.0.0.1', { [_TEST_ALLOW_LOOPBACK]: true }),
    /SSRF blocked/i
  );
});

test('Full scan against local hardened fixture vs vulnerable fixture verifies end-to-end scoring and findings', async () => {
  const goodRef = { origin: '' };
  const goodFx = await startFixtureServer(buildGoodSiteHandler(goodRef));
  goodRef.origin = goodFx.origin;

  const badFx = await startFixtureServer(buildBadSiteHandler());

  const [goodReport, badReport] = await Promise.all([
    scan(goodFx.origin, {
      [_TEST_ALLOW_LOOPBACK]: true,
      deep: true,
      performance: false,
      skipActive: false,
      maxPages: 10,
      maxDepth: 2,
    }),
    scan(badFx.origin, {
      [_TEST_ALLOW_LOOPBACK]: true,
      deep: true,
      performance: false,
      skipActive: false,
      maxPages: 10,
      maxDepth: 2,
    }),
  ]);

  // Hardened fixture checks
  assert.equal(goodReport.status, 200);
  assert.equal(goodReport.degraded, undefined, 'hardened non-SPA fixture must not be marked degraded');
  const unexpectedGoodHighs = goodReport.findings.filter(
    (f) => (f.severity === 'critical' || f.severity === 'high') && f.id !== 'no-https'
  );
  assert.deepEqual(unexpectedGoodHighs, [], 'hardened fixture should emit zero critical/high findings except no-https');
  assert.ok(goodReport.domains.compliance.score >= 85, `expected high compliance score, got ${goodReport.domains.compliance.score}`);
  assert.ok(goodReport.domains.seo.score >= 85, `expected high seo score, got ${goodReport.domains.seo.score}`);
  assert.ok(goodReport.domains.accessibility.score >= 90, `expected high a11y score, got ${goodReport.domains.accessibility.score}`);
  assert.ok(goodReport.domains.quality.score >= 90, `expected high quality score, got ${goodReport.domains.quality.score}`);
  assert.ok(goodReport.meta.crawledPages >= 2, `expected multi-page crawl, got ${goodReport.meta.crawledPages}`);
  assert.ok(
    goodReport.findings.every((f) => typeof f.whatItIs === 'string' && Array.isArray(f.exploitSteps) && f.exploitSteps.length > 0),
    'every finding must receive applyExplain knowledge metadata'
  );

  // Vulnerable fixture checks
  assert.equal(badReport.degraded, undefined);
  assert.ok((badReport.counts.critical || 0) >= 2, `expected >= 2 critical findings, got ${badReport.counts.critical}`);
  assert.ok((badReport.counts.high || 0) >= 1, `expected >= 1 high finding, got ${badReport.counts.high}`);
  assert.equal(badReport.scoreCeiling, 69);

  const badIds = new Set(badReport.findings.map((f) => f.id));
  for (const expectedId of [
    'exposed-path',
    'js-secret',
    'secret-leak',
    'cors-wildcard-credentials',
    'broken-link',
    'vuln-php-eol',
    'vuln-apache-outdated',
    'vuln-jquery-outdated',
    'no-consent',
    'seo-title',
    'seo-lang',
    'a11y-alt',
  ]) {
    assert.ok(badIds.has(expectedId), `expected vulnerable fixture to trigger ${expectedId}`);
  }
  assert.ok(
    badReport.domainAverage < goodReport.domainAverage,
    `vulnerable domainAverage (${badReport.domainAverage}) must be lower than hardened (${goodReport.domainAverage})`
  );
});

test('WAF-challenged local fixture sets degraded metadata, kind="waf", scoreCap=70, and unverified domain caps', async () => {
  const wafFx = await startFixtureServer(buildWafSiteHandler());
  const report = await scan(wafFx.origin, {
    [_TEST_ALLOW_LOOPBACK]: true,
    deep: true,
    performance: false,
    skipActive: true,
  });

  assert.equal(report.status, 403);
  assert.equal(report.meta.isWafChallenge, true);
  assert.equal(report.meta.wafProvider, 'Cloudflare');
  assert.equal(report.meta.headersHarvested, true);
  assert.ok(report.degraded && report.degraded.degraded === true);
  assert.equal(report.degraded.kind, 'waf');
  assert.equal(report.degraded.scoreCap, 70);
  assert.ok(report.score <= 70, `WAF score must be capped at 70, got ${report.score}`);
  assert.ok(['C', 'D', 'F'].includes(report.grade), `WAF grade cannot be A or B, got ${report.grade}`);

  const ids = new Set(report.findings.map((f) => f.id));
  assert.ok(ids.has('waf-challenge-intercepted'));
  assert.ok(ids.has('scan-degraded'));

  // Regression guard: Firecrawl-style/WAF challenge response CSP must not leak as origin unsafe-eval.
  assert.ok(!ids.has('csp-unsafe-eval'), 'Cloudflare 403 challenge CSP must never emit csp-unsafe-eval');

  for (const dom of ['compliance', 'performance', 'accessibility', 'seo']) {
    assert.equal(report.domains[dom].unverified, true, `${dom} must be marked unverified when checks were suspended`);
    assert.ok(report.domains[dom].score <= 70);
  }
});

test('Firecrawl WAF-bypass isolation skips challenge headers and flags unverified security cleanly', () => {
  const findings = [];
  const meta = { headersUnverified: true, headersHarvested: false, wafProvider: 'Cloudflare' };
  const bypassedRes = {
    url: 'https://protected.example.test/',
    status: 200,
    via: 'firecrawl',
    bypassedWaf: true,
    headersUnverified: true,
    headers: { 'content-type': 'text/html; charset=utf-8' },
    body: '<!DOCTYPE html><html lang="en"><head><title>Protected Example</title></head><body><h1>Hello</h1></body></html>',
    bytes: 105,
  };

  checkSecurityHeaders(bypassedRes, findings, meta);
  checkModernHeaders(bypassedRes, findings, meta);
  checkCookies(bypassedRes, findings, meta);
  checkCors(bypassedRes, findings, meta);
  checkQuality(bypassedRes.body, bypassedRes, findings, meta);

  const ids = new Set(findings.map((f) => f.id));
  assert.ok(!ids.has('hdr-strict-transport-security'), 'must not flag missing HSTS when origin headers were unverified');
  assert.ok(!ids.has('csp-unsafe-eval'), 'must not inherit Cloudflare challenge CSP');
  assert.ok(!ids.has('no-compression'), 'must not flag compression missing on Firecrawl HTML');
  assert.ok(!ids.has('no-cache'), 'must not flag cache missing on Firecrawl HTML');

  const deg = integrity.buildDegraded([integrity.HEADERS_UNVERIFIED_CAPABILITY], 'Origin headers unverified after WAF bypass');
  assert.equal(deg.kind, 'waf');
  assert.equal(deg.scoreCap, 79);

  const mockReport = {
    score: 94,
    grade: 'A',
    scoreCeiling: 100,
    degraded: null,
    domains: {
      security: { score: 100, grade: 'A', total: 1 },
      compliance: { score: 90, grade: 'A', total: 1 },
      performance: { score: 100, grade: 'A', total: 0 },
    },
  };
  integrity.applyDegraded(mockReport, deg);
  assert.equal(mockReport.score, 79);
  assert.equal(mockReport.scoreUncapped, 94);
  assert.equal(mockReport.domains.security.score, 79);
  assert.equal(mockReport.domains.security.unverified, true);
  assert.equal(mockReport.domains.performance.score, 100, 'verified CWV with 0 issues must stay 100');
  assert.equal(mockReport.domains.performance.unverified, undefined, 'verified performance domain must not be marked unverified');
});

test('detectTech ignores WordPress/Vercel strings in table links or ?q= URLs while detecting real assets', () => {
  const shLikeHtml = `<!DOCTYPE html><html lang="en"><head>
    <link rel="canonical" href="https://securityheaders.com/?q=https%3A%2F%2Fdemo.vercel.app%2F" />
    <script src="/assets/app.js"></script>
  </head><body>
    <table><tr><td><a href="/?q=https://my-site.vercel.app/wp-content/themes/x">my-site.vercel.app</a></td></tr></table>
    <p>Sample text mentioning wp-json and wp-includes</p>
  </body></html>`;

  const falseTech = detectTech({ headers: { server: 'cloudflare' } }, shLikeHtml);
  assert.ok(!falseTech.includes('WordPress'), `unexpected WordPress match: ${falseTech}`);
  assert.ok(!falseTech.includes('Vercel'), `unexpected Vercel match: ${falseTech}`);
  assert.ok(falseTech.includes('Cloudflare'));

  const realHtml = `<!DOCTYPE html><html><head>
    <link rel="stylesheet" href="/wp-content/themes/theme/style.css" />
    <script defer src="/_vercel/insights/script.js"></script>
  </head><body></body></html>`;
  const realTech = detectTech({ headers: {} }, realHtml);
  assert.ok(realTech.includes('WordPress'));
  assert.ok(realTech.includes('Vercel'));
});

test('publicReport and SQLite recordScan preserve degraded metadata and protect clean scans from degraded overwrites', () => {
  const report = {
    target: 'https://blocked.example.test',
    finalUrl: 'https://blocked.example.test/',
    status: 403,
    startedAt: '2026-11-23T12:00:00.000Z',
    durationMs: 1200,
    score: 70,
    scoreUncapped: 92,
    grade: 'C',
    scoreCeiling: 70,
    domainAverage: 75,
    domains: {
      security: { score: 85, grade: 'B', total: 2 },
      compliance: { score: 70, grade: 'C', total: 0, unverified: true },
      performance: { score: 70, grade: 'C', total: 0, unverified: true },
      accessibility: { score: 70, grade: 'C', total: 0, unverified: true },
      seo: { score: 70, grade: 'C', total: 0, unverified: true },
      quality: { score: 75, grade: 'C', total: 1 },
    },
    counts: { medium: 1, info: 1 },
    findings: [],
    meta: { wafProvider: 'Cloudflare', isWafChallenge: true },
    degraded: {
      degraded: true,
      kind: 'waf',
      capabilities: ['waf-intercepted'],
      reason: 'Cloudflare challenge',
      hint: 'Verify interactively',
      scoreCap: 70,
      unrunChecks: ['content heuristics'],
    },
  };

  const pub = leaderboard.publicReport(report);
  assert.equal(pub.scoreUncapped, 92);
  assert.equal(pub.degraded.kind, 'waf');
  assert.equal(pub.degraded.scoreCap, 70);
  assert.equal(pub.degraded.wafProvider, 'Cloudflare');
  assert.equal(pub.domains.compliance.unverified, true);

  // Exercise real SQLite schema/migration + recordScan/listLeaderboard in an isolated child process with temp DB.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vibescan-int-db-'));
  try {
    const out = execFileSync(
      process.execPath,
      [
        '-e',
        `
        const db = require('./lib/db');
        const lb = require('./lib/leaderboard');
        const degradedRep = JSON.parse(process.argv[1]);
        const r1 = db.recordScan(degradedRep, { deep: true });
        const list1 = db.latestListed(10);

        const cleanSiteRep = {
          target: 'https://clean-site.example.test',
          finalUrl: 'https://clean-site.example.test/',
          startedAt: '2026-11-23T12:05:00.000Z',
          durationMs: 900,
          score: 96,
          grade: 'A',
          domains: {
            security: { score: 96, grade: 'A', total: 1 },
            compliance: { score: 100, grade: 'A', total: 0 },
            performance: { score: 95, grade: 'A', total: 0 },
            accessibility: { score: 95, grade: 'A', total: 0 },
            seo: { score: 95, grade: 'A', total: 0 },
            quality: { score: 95, grade: 'A', total: 0 },
          },
          findings: [],
          meta: {},
        };
        const rClean = db.recordScan(cleanSiteRep, { deep: true });
        const laterWafOnClean = {
          ...degradedRep,
          target: 'https://clean-site.example.test',
          finalUrl: 'https://clean-site.example.test/',
          startedAt: '2026-11-23T12:10:00.000Z',
        };
        const rOverwrite = db.recordScan(laterWafOnClean, { deep: true });
        const url = new URL('http://localhost/api/leaderboard?view=top&scope=all');
        const boardRows = db.latestListed(10);
        const lbResult = boardRows.find((x) => x.host === 'clean-site.example.test');
        console.log(JSON.stringify({ r1, list1, rClean, rOverwrite, lbResult }));
        db.close();
        `,
        JSON.stringify(report),
      ],
      {
        cwd: path.join(__dirname, '..'),
        env: { ...process.env, VIBESCAN_DB_DIR: tmpDir },
      }
    ).toString();

    const parsed = JSON.parse(out);
    assert.equal(parsed.r1.isDegraded, true);
    assert.equal(parsed.list1[0].degraded, 1);
    assert.equal(parsed.list1[0].degraded_reason, 'waf');
    assert.equal(parsed.list1[0].score_cap, 70);
    assert.equal(parsed.rClean.isDegraded, false);
    assert.equal(parsed.rOverwrite.keptPreviousScan, true, 'degraded scan must not overwrite prior verified clean scan');
    assert.equal(parsed.lbResult.score, 96);
    assert.equal(parsed.lbResult.degraded, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Modular scanner.js preserves all expected public exports', () => {
  const expectedFns = [
    'scan',
    'rawRequest',
    'assertPublicHost',
    'checkQuality',
    'checkGoogleCrux',
    'detectTech',
    'checkTech',
    'checkPolicies',
    'scanSecrets',
    'detectWaf',
  ];
  for (const name of expectedFns) {
    assert.equal(typeof scanner[name], 'function', `expected ${name} export to be a function`);
  }
  assert.ok(scanner.EXPLAIN && typeof scanner.EXPLAIN === 'object');
  assert.ok(scanner.EXPLOIT && typeof scanner.EXPLOIT === 'object');
  assert.strictEqual(scanner.EXPLOIT_STEPS, scanner.EXPLOIT);
  assert.ok(scanner.egressState instanceof Map);
  assert.equal(typeof scanner._TEST_ALLOW_LOOPBACK, 'symbol');
});

test('deep.crawlSite preserves headersUnverified and runPageChecks skips header checks on crawled Firecrawl pages', async () => {
  const rootUrl = 'https://waf-crawl.example.test/';
  const subUrl = 'https://waf-crawl.example.test/?q=https%3A%2F%2Fexample.com%2F';
  const mockRawRequest = async (url) => {
    if (url === rootUrl) {
      return {
        url: rootUrl,
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        body: `<!DOCTYPE html><html lang="en"><head><title>Root</title></head><body><a href="${subUrl}">Sub</a></body></html>`,
        via: 'firecrawl',
        bypassedWaf: true,
        headersUnverified: true,
        wafProvider: 'Cloudflare',
        wafStatus: 403,
      };
    }
    return {
      url: subUrl,
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      body: '<!DOCTYPE html><html lang="en"><head><title>Sub</title></head><body><h1>Sub</h1></body></html>',
      via: 'firecrawl',
      bypassedWaf: true,
      headersUnverified: true,
      wafProvider: 'Cloudflare',
      wafStatus: 403,
    };
  };

  const crawl = await deep.crawlSite(rootUrl, mockRawRequest, { maxPages: 5, maxDepth: 1, concurrency: 2 });
  assert.equal(crawl.pages.length, 2);
  const subPage = crawl.pages.find((p) => p.url === subUrl);
  assert.ok(subPage, 'expected subpage in crawl result');
  assert.equal(subPage.headersUnverified, true);
  assert.equal(subPage.via, 'firecrawl');
  assert.equal(subPage.bypassedWaf, true);
  assert.equal(subPage.wafProvider, 'Cloudflare');
  assert.equal(subPage.wafStatus, 403);

  const subRes = runPageChecks(subPage, { headersUnverified: true, headersHarvested: false });
  const subIds = new Set(subRes.findings.map((f) => f.id));
  for (const forbidden of [
    'hdr-strict-transport-security',
    'hdr-content-security-policy',
    'hdr-x-content-type-options',
    'hdr-x-frame-options',
    'no-compression',
    'no-cache',
  ]) {
    assert.ok(!subIds.has(forbidden), `crawled Firecrawl page must not emit ${forbidden}`);
  }

  const wafPageCheck = runPageChecks({
    url: subUrl,
    status: 403,
    headers: { server: 'cloudflare', 'content-type': 'text/html' },
    body: '<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>Attention Required! Cloudflare</body></html>',
  });
  assert.equal(wafPageCheck.findings.length, 0);

  // Also verify an unharvested 403 WAF root skips crawling and marks security unverified under cap 70
  const unharvestedWafSrv = await startFixtureServer((req, res) => {
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      Server: 'cloudflare',
      'CF-RAY': '12345-LJU',
    });
    res.end('<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>Enable JavaScript and cookies to continue</body></html>');
  });
  const wafReport = await scan(unharvestedWafSrv.origin, {
    [_TEST_ALLOW_LOOPBACK]: true,
    deep: true,
    performance: false,
    skipActive: true,
  });
  assert.equal(wafReport.degraded.scoreCap, 70);
  assert.equal(wafReport.meta.crawledPages, 0);
  assert.equal(wafReport.domains.security.unverified, true);
});

test('_promoteChromeHeaders upgrades unverified WAF/Firecrawl scan using real top-level Chromium CDP headers', () => {
  const { _promoteChromeHeaders } = scanner;
  assert.equal(typeof _promoteChromeHeaders, 'function');

  const res = {
    url: 'https://protected.example.test/',
    status: 200,
    via: 'firecrawl',
    bypassedWaf: true,
    headersUnverified: true,
    headers: { 'content-type': 'text/html; charset=utf-8' },
    body: '<!DOCTYPE html><html lang="en"><head><title>Protected</title></head><body><h1>Protected</h1></body></html>',
    bytes: 95,
    tls: { authorized: true, protocol: 'TLSv1.3', daysToExpiry: 60 },
  };
  const findings = [
    { id: 'waf-headers-unverified', domain: 'security', severity: 'info', title: 'Unverified' },
  ];
  const meta = { headersUnverified: true, wafProvider: 'Cloudflare' };
  const degradedCaps = [integrity.HEADERS_UNVERIFIED_CAPABILITY];
  const degradedReasons = ['Origin HTTP headers unavailable after Cloudflare challenge bypass via Firecrawl'];
  const peripherals = { headers: res.headers };

  // Must refuse if Cloudflare challenge header is still present
  const rejected = _promoteChromeHeaders(
    res,
    {
      docStatus: 200,
      docHeaders: { server: 'cloudflare', 'cf-mitigated': 'challenge', 'content-type': 'text/html' },
      dom: res.body,
    },
    findings,
    meta,
    degradedCaps,
    degradedReasons,
    peripherals
  );
  assert.equal(rejected, false);
  assert.equal(meta.headersUnverified, true);

  // Must promote when Chromium received genuine HTTP 200 headers
  const promoted = _promoteChromeHeaders(
    res,
    {
      docStatus: 200,
      docHeaders: {
        server: 'cloudflare',
        'content-type': 'text/html; charset=utf-8',
        'content-encoding': 'gzip',
        'cache-control': 'public, max-age=60',
        'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'SAMEORIGIN',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=(), microphone=(), geolocation=()',
      },
      dom: res.body,
    },
    findings,
    meta,
    degradedCaps,
    degradedReasons,
    peripherals
  );
  assert.equal(promoted, true);
  assert.equal(meta.headersVerifiedViaChrome, true);
  assert.equal(meta.headersUnverified, false);
  assert.equal(res.headersUnverified, false);
  assert.equal(degradedCaps.length, 0);
  assert.equal(degradedReasons.length, 0);

  const ids = new Set(findings.map((f) => f.id));
  assert.ok(!ids.has('waf-headers-unverified'), 'waf-headers-unverified must be removed once headers are promoted');
  for (const missingHdr of [
    'hdr-strict-transport-security',
    'hdr-content-security-policy',
    'hdr-x-content-type-options',
    'hdr-x-frame-options',
    'hdr-referrer-policy',
    'hdr-permissions-policy',
    'no-compression',
    'no-cache',
  ]) {
    assert.ok(!ids.has(missingHdr), `promoted Chromium headers should satisfy ${missingHdr}`);
  }
});

test('checkModernHeaders respects enforced CSP default-src fallback for object-src', () => {
  const runCsp = (headers) => {
    const f = [];
    checkModernHeaders(
      { url: 'https://example.test/', status: 200, headers, body: '' },
      f,
      { headersUnverified: false }
    );
    return f.find((x) => x.id === 'csp-no-object-src') || null;
  };

  assert.equal(runCsp({ 'content-security-policy': "default-src 'none'; script-src 'self'" }), null);

  const selfOnly = runCsp({ 'content-security-policy': "default-src 'self'; script-src 'self'" });
  assert.ok(selfOnly);
  assert.equal(selfOnly.severity, 'low');

  const multiOrigin = runCsp({ 'content-security-policy': "default-src 'self' https://cdn.example.com" });
  assert.ok(multiOrigin);
  assert.equal(multiOrigin.severity, 'medium');

  const reportOnlyDefaultNone = runCsp({
    'content-security-policy': "script-src 'self'",
    'content-security-policy-report-only': "default-src 'none'",
  });
  assert.ok(reportOnlyDefaultNone);
  assert.equal(reportOnlyDefaultNone.severity, 'medium');
});

test('checkCookies skips HttpOnly on CSRF/UI cookies while keeping Secure/SameSite and full session checks', () => {
  const csrfFindings = [];
  checkCookies(
    {
      url: 'https://example.test/',
      status: 200,
      headers: { 'set-cookie': ['anti_forgery_cookie=abc123; Path=/'] },
      body: '',
    },
    csrfFindings,
    { headersUnverified: false }
  );
  const csrfIds = new Set(csrfFindings.map((f) => f.id));
  assert.ok(csrfIds.has('cookie-insecure-anti_forgery_cookie'));
  assert.ok(csrfIds.has('cookie-samesite-anti_forgery_cookie'));
  assert.equal(csrfIds.has('cookie-httponly-anti_forgery_cookie'), false);
  assert.equal(csrfFindings.find((f) => f.id === 'cookie-insecure-anti_forgery_cookie').severity, 'medium');

  const sidFindings = [];
  checkCookies(
    {
      url: 'https://example.test/',
      status: 200,
      headers: { 'set-cookie': ['sid=deadbeef; Path=/'] },
      body: '',
    },
    sidFindings,
    { headersUnverified: false }
  );
  const sidIds = new Set(sidFindings.map((f) => f.id));
  assert.ok(sidIds.has('cookie-insecure-sid'));
  assert.ok(sidIds.has('cookie-httponly-sid'));
  assert.ok(sidIds.has('cookie-samesite-sid'));
});

test('scoreByDomain and penaltyToScore cap per-domain low hygiene penalty at 15 while keeping serious findings uncapped', () => {
  assert.equal(MAX_LOW_PENALTY_PER_DOMAIN, 15);

  const tenLows = Array.from({ length: 10 }, (_, i) => ({
    id: `low-${i}`,
    domain: 'security',
    severity: 'low',
  }));
  const d1 = scoreByDomain(tenLows);
  assert.equal(d1.security.penalty, 15);
  assert.equal(d1.security.score, 85);
  assert.equal(d1.security.grade, 'B');
  assert.equal(penaltyToScore(tenLows), 85);

  const oneMedNineLows = [
    { id: 'med-1', domain: 'security', severity: 'medium' },
    ...Array.from({ length: 9 }, (_, i) => ({
      id: `low-${i}`,
      domain: 'security',
      severity: 'low',
    })),
  ];
  const d2 = scoreByDomain(oneMedNineLows);
  assert.equal(d2.security.penalty, 23);
  assert.equal(d2.security.score, 77);
  assert.equal(d2.security.grade, 'C');

  const complianceMix = [
    { id: 'h-1', domain: 'compliance', severity: 'high' },
    { id: 'h-2', domain: 'compliance', severity: 'high' },
    { id: 'm-1', domain: 'compliance', severity: 'medium' },
    { id: 'm-2', domain: 'compliance', severity: 'medium' },
    { id: 'l-1', domain: 'compliance', severity: 'low' },
  ];
  const d3 = scoreByDomain(complianceMix);
  assert.equal(d3.compliance.penalty, 49);
  assert.equal(d3.compliance.score, 51);
  assert.equal(d3.compliance.grade, 'F');
});
