'use strict';
/**
 * VibeScan core engine orchestrator — zero external dependencies.
 *
 * Coordinates the scan phases across modular subsystems under `lib/scanner/`:
 *   - ssrf.js         IPv4/IPv6 CIDR validation & DNS rebinding protection
 *   - http.js         Egress proxy chaining, HTTP/TLS transport & circuit breaker
 *   - findings.js     Finding factory helpers, weights & legal-policy rules
 *   - patterns.js     Secret regexes & WAF / bot-challenge detection
 *   - knowledge.js    Human-readable EXPLAIN / EXPLOIT knowledge base
 *   - tech.js         Tech fingerprinting & vulnerable runtime detection
 *   - headers.js      Transport, security headers, cookies & CORS checks
 *   - content.js      HTML body, GDPR compliance, SEO & asset quality checks
 *   - peripherals.js  Peripherals (/robots.txt, etc.), DNS, paths, bundles & links
 *   - scoring.js      Scoring v2 domain averages, ceilings & crawl merging
 *
 * SSRF protection: every DNS resolution is validated and private / reserved
 * ranges are refused before any outbound request is made.
 */

const net = require('net');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');

const deep = require('./deep');
const webvitals = require('./webvitals'); // Phase 3 — Core Web Vitals lab metrics
const a11y = require('./a11y');           // Phase 4 — accessibility (WCAG 2.2 AA / EAA)
const eu = require('./eu');               // Phase 5 — EU compliance deepening
const probes = require('./probes');       // Phase 6 — active-but-safe security surface
const seoLib = require('./seo');          // Phase 7 — SEO / AI discoverability 2026
const integrity = require('./integrity'); // P0 — degrade loudly, never silently
const buildfp = require('./buildfp');     // leaderboard — provenance fingerprint (compact)
const ctRecon = require('./ct-recon');    // Certificate Transparency reconnaissance engine

const { ALLOW_LOOPBACK_TEST, assertPublicHost } = require('./scanner/ssrf');
const { UA, rawRequest, egressState } = require('./scanner/http');
const { makeFinding, mkA11y, mkPerf, mkEu, mkProbe, mkSeo } = require('./scanner/findings');
const { scanSecrets, detectWaf, isWafChallenge } = require('./scanner/patterns');
const { EXPLAIN, EXPLOIT, EXPLOIT_STEPS, applyExplain } = require('./scanner/knowledge');
const { detectTech, checkTech } = require('./scanner/tech');
const {
  checkTransport,
  checkSecurityHeaders,
  checkModernHeaders,
  checkCookies,
  checkCors,
} = require('./scanner/headers');
const {
  checkBody,
  checkPolicies,
  checkCompliance,
  checkSeo,
  checkQuality,
} = require('./scanner/content');
const {
  fetchPeripheral,
  checkDnsSecurity,
  checkPathExposure,
  collectScripts,
  checkJsBundles,
  checkBrokenLinks,
} = require('./scanner/peripherals');
const {
  scoreCeiling,
  scoreFindings,
  scoreByDomain,
  runPageChecks,
  mergePageFindings,
} = require('./scanner/scoring');

// Ensure FIRECRAWL_API_KEY is loaded if not already in process.env
if (!process.env.FIRECRAWL_API_KEY) {
  for (const envFile of ['/etc/vibescan/public.env', path.join(__dirname, '../.env')]) {
    try {
      if (fs.existsSync(envFile)) {
        const content = fs.readFileSync(envFile, 'utf8');
        for (const line of content.split('\n')) {
          const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)?\s*$/);
          if (match && !process.env[match[1]]) {
            process.env[match[1]] = match[2] ? match[2].trim().replace(/^['"](.*)['"]$/, '$1') : '';
          }
        }
      }
    } catch {}
  }
}

/* ------------------------------------------------------------------ *
 * Phase 3–7 module runners
 * ------------------------------------------------------------------ */

// Run a best-effort check block; never let a module bug abort the scan.
function safeRun(fn, label, meta) {
  try {
    fn();
  } catch (e) {
    meta.moduleErrors = meta.moduleErrors || {};
    meta.moduleErrors[label] = e.message;
  }
}

/**
 * Phase 7 / Performance — Google CrUX / PageSpeed Field Data (28-day Chrome user sample).
 * Best-effort external API lookup with a 5s timeout. If Google rate-limits,
 * times out, or fails, the main scan completes unaffected.
 */
async function checkGoogleCrux(targetUrl, findings, meta, mkSeoFn, mkPerfFn) {
  try {
    const apiKey = process.env.PAGESPEED_API_KEY || process.env.CRUX_API_KEY || process.env.GOOGLE_API_KEY || '';
    let apiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(targetUrl)}&strategy=mobile`;
    if (apiKey) apiUrl += `&key=${encodeURIComponent(apiKey)}`;

    const res = await fetch(apiUrl, {
      signal: AbortSignal.timeout(5000),
      headers: { Accept: 'application/json', 'User-Agent': UA },
    });

    if (!res.ok) {
      meta.crux = { category: 'UNAVAILABLE', reason: 'Api unavailable or rate limited' };
      return;
    }
    const data = await res.json();
    const exp = data && (data.loadingExperience || data.originLoadingExperience);
    const overall = exp && (exp.overall_category || '').toUpperCase();
    if (!exp || !overall || overall === 'NONE') {
      meta.crux = { category: 'INSUFFICIENT_DATA', label: 'Ni zadostnega 28d obiska za terenski vzorec' };
      return;
    }

    const metrics = {};
    if (exp.metrics) {
      if (exp.metrics.LARGEST_CONTENTFUL_PAINT_MS && exp.metrics.LARGEST_CONTENTFUL_PAINT_MS.percentile != null) {
        metrics.lcp = exp.metrics.LARGEST_CONTENTFUL_PAINT_MS.percentile;
      }
      if (exp.metrics.INTERACTION_TO_NEXT_PAINT && exp.metrics.INTERACTION_TO_NEXT_PAINT.percentile != null) {
        metrics.inp = exp.metrics.INTERACTION_TO_NEXT_PAINT.percentile;
      }
      if (exp.metrics.CUMULATIVE_LAYOUT_SHIFT_SCORE && exp.metrics.CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile != null) {
        const rawCls = exp.metrics.CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile;
        metrics.cls = rawCls > 2 ? rawCls / 100 : rawCls;
      }
    }

    meta.crux = { category: overall, metrics };

    const parts = [];
    if (metrics.lcp != null) parts.push(`LCP: ${metrics.lcp}ms`);
    if (metrics.inp != null) parts.push(`INP: ${metrics.inp}ms`);
    if (metrics.cls != null) parts.push(`CLS: ${Number(metrics.cls).toFixed(2)}`);
    const ev = parts.length ? `Google CrUX 28-day field percentiles: ${parts.join(', ')} (Category: ${overall})` : `Google CrUX Category: ${overall}`;

    if (overall === 'FAST') {
      findings.push(mkSeoFn(
        'crux-field-fast',
        'info',
        'Passes Google Core Web Vitals assessment in real-user field data (CrUX)',
        'Google CrUX 28-day data confirms real Chrome users experience fast loading and smooth interactivity on mobile devices.',
        'Maintain current frontend performance optimizations, caching, and asset budgets.',
        ev
      ));
    } else if (overall === 'SLOW') {
      findings.push(mkPerfFn(
        'crux-field-slow',
        'low',
        'Fails Google Core Web Vitals assessment in real-user field data (CrUX)',
        '28-day Chrome user field data shows significant user experience bottlenecks, which directly damages Google search ranking.',
        'Optimize LCP (compress hero images, preload critical fonts), eliminate long main-thread tasks to lower INP, and reserve layout dimensions to prevent CLS.',
        ev
      ));
    }
  } catch (e) {
    if (!meta.crux) {
      meta.crux = { category: 'UNAVAILABLE', reason: e.message || 'Lookup timeout or error' };
    }
  }
}

// Phase 6 — active-but-safe security surface (skipped when skipActive is true).
// All probes are non-destructive GET/HEAD/OPTIONS indicators using rawRequest.
async function runProbes(html, origin, findings, meta, primaryIp, bypassProxy = false, skipActive = false, reqFn = rawRequest, { skipShodan = false } = {}) {
  const jsText = meta.jsBundleText || '';
  const raw = (u, o) => reqFn(u, { ...o, bypassProxy: bypassProxy || (o && o.bypassProxy) });
  const ip = primaryIp || (meta && meta.primaryIp);
  const probeOpts = { skipActive: Boolean(skipActive) };
  const tasks = [
    ['open-redirect', () => probes.checkOpenRedirect(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['reflected-input', () => probes.checkReflectedInput(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['host-header', () => probes.checkHostHeader(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['http-methods', () => probes.checkHttpMethods(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['directory-listing', () => probes.checkDirectoryListing(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['crossdomain-policy', () => probes.checkCrossdomainPolicy(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['graphql-introspection', () => probes.checkGraphqlIntrospection(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['api-error-verbose', () => probes.checkApiErrorVerbosity(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['open-buckets', () => probes.checkOpenBuckets(html, jsText, raw, findings, meta, mkProbe, probeOpts)],
    ['sensitive-files', () => probes.checkSensitiveFiles(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['source-maps', () => probes.checkSourceMaps(origin, html, raw, findings, meta, mkProbe, probeOpts)],
    ['cors-misconfig', () => probes.checkCorsMisconfiguration(origin, raw, findings, meta, mkProbe, probeOpts)],
    ['admin-debug', () => probes.checkAdminDebugEndpoints(origin, raw, findings, meta, mkProbe, probeOpts)],
  ];
  if (!skipShodan) {
    tasks.push(['shodan', () => probes.checkShodan(ip, findings, meta, mkProbe)]);
  }
  await Promise.all(tasks.map(async ([label, fn]) => {
    try { await fn(); } catch (e) {
      meta.probes = meta.probes || {};
      meta.probes[label] = { error: e.message };
    }
  }));

  // Synchronous (no network) surface checks. These push into the array given.
  safeRun(() => probes.checkWebSockets(html, jsText, origin, findings, meta, mkProbe), 'ws', meta);
  safeRun(() => probes.checkSupplyChain(html, origin, findings, meta, mkProbe), 'supply-chain', meta);
  safeRun(() => probes.checkExtendedSecrets(html, jsText, findings, meta, mkProbe), 'secrets-ext', meta);
}

/* ------------------------------------------------------------------ *
 * Chromium CDP header promotion (when Node HTTP was WAF-blocked / Firecrawl-only
 * yet headless Chromium cleared the challenge and received real HTTP 200 headers)
 * ------------------------------------------------------------------ */

const STALE_HEADER_PREFIXES = ['hdr-', 'csp-', 'coop-', 'coep-', 'corp-', 'cors-', 'disclosure-', 'vuln-', 'cookie-', 'hsts-'];
const STALE_HEADER_EXACT = new Set([
  'referrer-policy',
  'permissions-policy',
  'no-compression',
  'no-cache',
  'http-redirect',
  'no-https',
  'tls-untrusted',
  'tls-expiring',
  'tls-old-protocol',
  'deprecated-document-domain',
  'waf-headers-unverified',
  'waf-challenge-intercepted',
]);

function promoteChromeHeaders(res, live, findings, meta, degradedCaps, degradedReasons, peripherals) {
  if (!res || (!res.headersUnverified && !meta.isWafChallenge)) return false;
  if (!live || typeof live.docStatus !== 'number' || live.docStatus < 200 || live.docStatus >= 400) return false;
  if (!live.docHeaders || typeof live.docHeaders !== 'object') return false;

  const chromeHeaders = {};
  for (const [k, v] of Object.entries(live.docHeaders)) {
    if (v === undefined || v === null) continue;
    chromeHeaders[String(k).toLowerCase()] = Array.isArray(v) ? v.slice() : String(v);
  }
  if (Object.keys(chromeHeaders).length < 2) return false;
  if (chromeHeaders['cf-mitigated']) return false;
  if (detectWaf({ status: live.docStatus, headers: chromeHeaders }, live.dom || '').isWaf) return false;

  const hadWafRoot = Boolean(meta.isWafChallenge);
  res.headers = chromeHeaders;
  res.status = live.docStatus;
  res.headersUnverified = false;
  if (hadWafRoot && live.dom && live.dom.length > 0) {
    res.body = live.dom;
    res.bytes = Buffer.byteLength(live.dom, 'utf8');
  }

  meta.isWafChallenge = false;
  meta.headersUnverified = false;
  meta.headersHarvested = false;
  meta.headersVerifiedViaChrome = true;
  if (peripherals && typeof peripherals === 'object') {
    peripherals.headers = res.headers;
  }

  if (Array.isArray(degradedCaps)) {
    for (let i = degradedCaps.length - 1; i >= 0; i--) {
      if (degradedCaps[i] === integrity.HEADERS_UNVERIFIED_CAPABILITY) degradedCaps.splice(i, 1);
    }
  }
  if (Array.isArray(degradedReasons)) {
    for (let i = degradedReasons.length - 1; i >= 0; i--) {
      if (/origin http headers unavailable/i.test(String(degradedReasons[i]))) degradedReasons.splice(i, 1);
    }
  }

  for (let i = findings.length - 1; i >= 0; i--) {
    const id = String(findings[i].id || '');
    if (STALE_HEADER_EXACT.has(id) || STALE_HEADER_PREFIXES.some((p) => id.startsWith(p))) {
      findings.splice(i, 1);
    }
  }

  checkTransport(res, findings, meta);
  checkSecurityHeaders(res, findings, meta);
  checkModernHeaders(res, findings, meta);
  checkCookies(res, findings, meta);
  checkCors(res, findings, meta);
  checkTech(res, res.body, findings, meta);

  const qFindings = [];
  checkQuality(live.dom || res.body, res, qFindings, meta);
  for (const f of qFindings) {
    if ((f.id === 'no-compression' || f.id === 'no-cache') && !findings.some((x) => x.id === f.id)) {
      findings.push(f);
    }
  }

  if (hadWafRoot && (live.dom || res.body)) {
    const bodyDoc = live.dom || res.body;
    const bodyRec = [];
    checkBody(bodyDoc, res, bodyRec, meta);
    if (peripherals) checkCompliance(bodyDoc, res, bodyRec, meta, peripherals);
    for (const f of bodyRec) {
      if (!findings.some((x) => x.id === f.id)) findings.push(f);
    }
  }

  return true;
}

/* ------------------------------------------------------------------ *
 * Public entrypoint
 * ------------------------------------------------------------------ */

async function scan(inputTarget, options = {}) {
  const started = Date.now();
  const findings = [];
  const meta = {};
  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;

  const allowLoopback = Boolean(options && options[ALLOW_LOOPBACK_TEST] === true);
  const skipExternalLookups = allowLoopback || options.skipExternalLookups === true;
  const hostCheckOpts = allowLoopback ? { [ALLOW_LOOPBACK_TEST]: true } : null;
  const reqFn = allowLoopback
    ? (u, o = {}) => rawRequest(u, { ...o, [ALLOW_LOOPBACK_TEST]: true, bypassProxy: true })
    : rawRequest;

  onProgress && onProgress('dns', { phaseIdx: 0, msg: 'Preverjam DNS zapise in TLS certifikat …' });

  // P0 — capabilities expected but missing, collected during the scan so the
  // finished report can be marked `degraded` and have its score capped.
  const degradedCaps = [];
  const degradedReasons = [];

  const deepScan = options.deep !== false;          // master switch
  const skipActive = options.skipActive !== undefined ? Boolean(options.skipActive) : process.env.VIBESCAN_PUBLIC === '1';
  meta.scanMode = skipActive ? 'passive' : 'active';
  const maxPages = Math.min(Math.max(parseInt(options.maxPages, 10) || 25, 1), 60);
  const maxDepth = Math.min(Math.max(parseInt(options.maxDepth, 10) || 2, 0), 4);

  // Auth-aware scanning: caller-supplied headers (e.g. a session Cookie) are
  // applied to the initial fetch so private/staging sites can be audited.
  // Never logged, never persisted into the report.
  const authHeaders = (options.headers && typeof options.headers === 'object') ? options.headers : null;

  let target = (inputTarget || '').trim();
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

  const resolvedHost = await assertPublicHost(new URL(target).hostname, hostCheckOpts);
  const resolvedIp = resolvedHost.addresses.join(', ');

  const maxRedirects = options.followRedirects === false ? 0 : 5;
  const usedBypassProxy = allowLoopback;
  // The scan must egress through SCANNER_PROXY. It previously retried a failed
  // proxied fetch directly from the host, which leaked the host's public IP to
  // the target. A failed proxied request is a real result, not a prompt to
  // reveal our own address.
  const res = await reqFn(target, { headers: authHeaders, maxRedirects });

  // A 403/429/WAF challenge from the proxied request is the answer. It used to
  // trigger a direct retry from the host IP so "real headers could be captured";
  // that revealed our own address to the target, which is exactly what the
  // proxy exists to prevent. Report the block instead.
  if (!allowLoopback && require('./egress').tiers().length > 0 && (res.status === 403 || res.status === 429 || isWafChallenge(res, res.body))) {
    meta.proxiedBlocked = true;
  }

  const origin = new URL(res.url).origin;

  // The headless renderer must pin DNS to the *final* host's validated public
  // IP (the target may have redirected to a different hostname).
  const finalHost = new URL(res.url).hostname;
  const finalResolved = finalHost === new URL(target).hostname
    ? resolvedHost
    : await assertPublicHost(finalHost, hostCheckOpts).catch(() => resolvedHost);
  const primaryIp = finalResolved.addresses.find((a) => net.isIPv4(a)) || finalResolved.addresses[0];
  meta.primaryIp = primaryIp;

  const wafCheck = detectWaf(res, res.body);
  if (wafCheck.isWaf) {
    meta.isWafChallenge = true;
    meta.wafProvider = wafCheck.provider || 'WAF';
  }

  // Never bypass the proxy for peripherals.
  const peripheralBypass = allowLoopback;
  const [robots, sitemap, securityTxt, llms, llmsFull] = await Promise.all([
    fetchPeripheral(origin, '/robots.txt', peripheralBypass, reqFn),
    fetchPeripheral(origin, '/sitemap.xml', peripheralBypass, reqFn),
    fetchPeripheral(origin, '/.well-known/security.txt', peripheralBypass, reqFn),
    fetchPeripheral(origin, '/llms.txt', peripheralBypass, reqFn),
    fetchPeripheral(origin, '/llms-full.txt', peripheralBypass, reqFn),
  ]);

  const HARVEST_SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'content-security-policy-report-only',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-opener-policy',
    'cross-origin-embedder-policy',
    'cross-origin-resource-policy',
    'x-xss-protection',
  ];

  // Never let HTTP 403/429 WAF challenge headers (e.g. Cloudflare's interstitial
  // `content-security-policy` containing `'unsafe-eval'`) masquerade as origin headers.
  if (meta.isWafChallenge || res.headersUnverified) {
    for (const hdr of HARVEST_SECURITY_HEADERS) {
      delete res.headers[hdr];
    }
  }

  if (robots && robots.status === 200 && robots.headers) {
    const harvested = [];
    for (const hdr of HARVEST_SECURITY_HEADERS) {
      if (robots.headers[hdr] && (!res.headers[hdr] || meta.isWafChallenge || res.headersUnverified)) {
        res.headers[hdr] = robots.headers[hdr];
        harvested.push(hdr);
      }
    }
    if (harvested.length > 0) {
      meta.headersHarvested = true;
      meta.harvestedHeaders = harvested;
    }
  }

  if (res.headersUnverified || res.via === 'firecrawl' || res.bypassedWaf) {
    meta.headersUnverified = true;
    if (res.wafProvider && !meta.wafProvider) meta.wafProvider = res.wafProvider;
    if (!meta.headersHarvested && !meta.isWafChallenge) {
      const providerName = meta.wafProvider || 'WAF';
      findings.push(makeFinding({
        id: 'waf-headers-unverified',
        domain: 'security',
        severity: 'info',
        title: `Origin HTTP security headers could not be verified (${providerName} challenge)`,
        detail: `Initial request received HTTP ${res.wafStatus || 403} from ${providerName}; page HTML was retrieved via Firecrawl, which does not expose origin HTTP response headers, and /robots.txt did not return them. Header, cookie, and CORS checks were skipped instead of scoring WAF challenge headers.`,
        fix: 'Allowlist the scanner IP or verify security headers directly from a trusted client.',
      }));
      degradedCaps.push(integrity.HEADERS_UNVERIFIED_CAPABILITY);
      degradedReasons.push(`Origin HTTP headers unavailable after ${providerName} challenge bypass via Firecrawl`);
    }
  }

  if (meta.isWafChallenge) {
    const providerName = meta.wafProvider || 'WAF';
    findings.push(makeFinding({
      id: 'waf-challenge-intercepted',
      domain: 'security',
      severity: 'info',
      title: `WAF / Bot challenge intercepted request (${providerName})`,
      detail: `The domain is protected by ${providerName} Bot Management / WAF which intercepted the automated request (HTTP ${res.status}). Content-level heuristics (SEO tags, legal links, accessibility) were suspended to avoid false positives on the interstitial challenge markup.${meta.headersHarvested ? ` Origin security headers (${meta.harvestedHeaders.join(', ')}) were successfully harvested via /robots.txt.` : ''}`,
      fix: 'No fix needed; this indicates active DDoS and automated bot challenge protection.',
    }));
  }

  onProgress && onProgress('headers', { phaseIdx: 1, msg: 'Preverjam varnostne glave in piškotke …' });

  checkTransport(res, findings, meta);
  checkSecurityHeaders(res, findings, meta);
  checkModernHeaders(res, findings, meta);
  checkCookies(res, findings, meta);
  checkBody(res.body, res, findings, meta);
  checkCors(res, findings, meta);
  checkTech(res, res.body, findings, meta);

  const peripherals = { robots, sitemap, securityTxt, llms, llmsFull, headers: res.headers };

  checkCompliance(res.body, res, findings, meta, peripherals);
  checkSeo(res.body, res, findings, meta, peripherals);
  checkQuality(res.body, res, findings, meta);

  // ---- Phase 4/5/6/7 module wiring (each is best-effort, non-fatal) ----
  if (!meta.isWafChallenge) {
    safeRun(() => {
      for (const f of eu.checkEuCompliance(res.body, res, findings, meta, peripherals, mkEu)) findings.push(f);
    }, 'eu', meta);
    safeRun(() => {
      for (const f of a11y.checkA11yStatic(res.body, [], meta, mkA11y)) findings.push(f);
    }, 'a11y-static', meta);
    // The seo module pushes straight into the array it is given (no return value).
    safeRun(() => {
      seoLib.checkJsonLd(res.body, origin, findings, meta, mkSeo, peripherals, res);
      seoLib.checkIndexability(res.body, origin, res, findings, meta, mkSeo, peripherals);
    }, 'seo-2026', meta);
  }
  safeRun(() => {
    seoLib.checkAiCrawlerPolicy(res.body, origin, findings, meta, mkSeo, peripherals);
  }, 'seo-ai-policy', meta);

  const apexHost = (new URL(res.url).hostname || '').replace(/^www\./i, '');

  // Extended sweeps — run concurrently, each is best-effort. checkJsBundles
  // must finish first: it populates meta.jsBundleText which the Phase 6 probes
  // (buckets / WebSockets / secrets / PII) then scan.
  await Promise.all([
    checkDnsSecurity(new URL(res.url).hostname, res, findings, meta, reqFn),
    skipActive ? Promise.resolve() : checkPathExposure(origin, findings, meta, reqFn),
    checkJsBundles(res.body, origin, findings, meta, reqFn),
    checkBrokenLinks(res.body, origin, findings, meta, reqFn),
    skipExternalLookups ? Promise.resolve() : checkGoogleCrux(res.url, findings, meta, mkSeo, mkPerf),
    skipExternalLookups
      ? Promise.resolve()
      : ctRecon.checkSubdomains(apexHost, findings, meta, mkProbe).catch((e) => {
          meta.ct = { count: 0, sample: [], staging: [], admin: [], error: e.message };
        }),
  ]);
  await runProbes(res.body, origin, findings, meta, primaryIp, usedBypassProxy, skipActive, reqFn, {
    skipShodan: skipExternalLookups,
  });

  /* ---------------------------------------------------------------- *
   * DEEP LAYER (opt-in via options.deep, on by default):
   *   1. headless render  — scan the post-JS DOM for SPAs
   *   2. BFS crawl        — sweep the whole same-origin site
   *   3. Firecrawl map    — optional extra subpage discovery
   * ---------------------------------------------------------------- */
  if (deepScan) {
    const deepMeta = {};
    const effectiveRes = { ...res };

    // (1) Headless render if the HTML looks like a client-rendered shell.
    if (!meta.isWafChallenge && deep.looksLikeSpa(res.body)) {
      const rendered = await deep.renderWithHeadless(res.url, primaryIp, { bypassProxy: allowLoopback });
      deepMeta.render = { attempted: true, ok: !!rendered.ok, length: rendered.length || 0, error: rendered.error || null };
      if (!rendered.ok && options.performance === false) {
        // The page is a JS shell and we could not render it: its body was never
        // really scanned, so several content checks never ran. Degrade.
        degradedCaps.push(integrity.RENDER_CAPABILITY);
        degradedReasons.push(rendered.error || 'SPA render failed');
      }
      if (rendered.ok && rendered.dom && rendered.dom.length > res.body.length) {
        effectiveRes.body = rendered.dom;
        meta.rendered = true;
        // Held only for the fingerprint pass below, then deleted — the rendered
        // HTML must never be persisted (PLAN-LEADERBOARD.md §2.1).
        meta.renderBody = rendered.dom;
        // Re-run content-based checks on the rendered DOM (headers/TLS stay same).
        const renderedFindings = [];
        checkBody(rendered.dom, effectiveRes, renderedFindings, meta);
        for (const f of renderedFindings) {
          if (!findings.some((x) => x.id === f.id)) findings.push(f);
        }
      }
    }

    // (1b) Phase 3 + Phase 4 — one headless pass yields Core Web Vitals lab
    // metrics, computed-style contrast data, and the post-JS DOM for the
    // rendered a11y suite. Opt out with options.performance === false.
    if (options.performance !== false) {
      onProgress && onProgress('cwv', { phaseIdx: 2, msg: 'Merim hitrost delovanja in Core Web Vitals …' });
      try {
        const live = await webvitals.measure(res.url, { resolvedIp: primaryIp, timeoutMs: 28000, bypassProxy: usedBypassProxy });
        if (live.ok) {
          deepMeta.performance = { ok: true };

          const domDocStatus = live.docStatus || (live.metrics && live.metrics.docStatus) || 0;
          const domWaf = detectWaf({ status: domDocStatus || res.status, headers: live.docHeaders || res.headers }, live.dom);
          const isDomErrorOrBlock = (domDocStatus === 403 || domDocStatus === 429 || domDocStatus === 503) ||
            domWaf.isWaf ||
            /<title>[^<]*(?:Just a moment|Security Checkpoint|Checking your browser|Attention Required|Cloudflare|ddos protection|403 Forbidden|Access Denied|Error 403|429 Too Many|503 Service)[^<]*<\/title>/i.test(live.dom) ||
            /<h[12]>[^<]*(?:403\s+Forbidden|Access\s+Denied|Request\s+forbidden)[^<]*<\/h[12]>/i.test(live.dom) ||
            /\/hcdn-cgi\/jschallenge|challenges\.cloudflare\.com|geo\.captcha-delivery\.com/i.test(live.dom) ||
            (/openresty|nginx/i.test(live.dom) && /403\s+Forbidden/i.test(live.dom) && live.dom.length < 4096);

          // Only score CWV and promote verified top-level HTTP headers when Headless Chrome rendered the real page.
          if (!isDomErrorOrBlock) {
            promoteChromeHeaders(res, live, findings, meta, degradedCaps, degradedReasons, peripherals);
            meta.cwv = live.metrics || null;
            const perfFindings = [];
            safeRun(() => seoLib.checkCwv(live.metrics, perfFindings, meta, mkPerf), 'cwv', meta);
            for (const f of perfFindings) {
              if (!findings.some((x) => x.id === f.id)) findings.push(f);
            }
          }

          if (isDomErrorOrBlock) {
            const originWaf = detectWaf(res, res.body);
            const originBlocked = res.status === 403 || res.status === 429 || originWaf.isWaf || !res.body;
            if (originBlocked) {
              meta.isWafChallenge = true;
              if (!meta.wafProvider && domWaf.provider) meta.wafProvider = domWaf.provider;
              if (!findings.some((x) => x.id === 'waf-challenge-intercepted')) {
                const providerName = meta.wafProvider || 'WAF';
                findings.push(makeFinding({
                  id: 'waf-challenge-intercepted',
                  domain: 'security',
                  severity: 'info',
                  title: `WAF / Bot challenge intercepted request (${providerName})`,
                  detail: `The domain is protected by ${providerName} Bot Management / WAF which intercepted the automated request (HTTP ${res.status}). Content-level heuristics (SEO tags, legal links, accessibility) were suspended to avoid false positives on the interstitial challenge markup.${meta.headersHarvested ? ` Origin security headers (${meta.harvestedHeaders.join(', ')}) were successfully harvested via /robots.txt.` : ''}`,
                  fix: 'No fix needed; this indicates active DDoS and automated bot challenge protection.',
                }));
              }
            } else {
              // Origin HTML is authentic (HTTP 200, full payload); Headless Chrome encountered a checkpoint or 403 block.
              // Skip DOM reconciliation to avoid scanning checkpoint interstitial, but do NOT degrade scan.
              meta.domChallengeBypassed = false;
              if (res.via === 'firecrawl' && res.body) {
                meta.renderBody = res.body;
              }
            }
          } else if (live.dom && live.dom.length > 0) {
            meta.renderBody = live.dom;
            const domRes = { ...res, body: live.dom };
            const postJsFindings = [];
            checkSeo(live.dom, domRes, postJsFindings, meta, peripherals);
            checkQuality(live.dom, domRes, postJsFindings, meta);
            safeRun(() => {
              for (const f of a11y.checkA11yStatic(live.dom, [], meta, mkA11y)) postJsFindings.push(f);
            }, 'a11y-static-reconcile', meta);
            safeRun(() => {
              seoLib.checkJsonLd(live.dom, origin, postJsFindings, meta, mkSeo, peripherals, domRes);
              seoLib.checkAiCrawlerPolicy(live.dom, origin, postJsFindings, meta, mkSeo, peripherals);
              seoLib.checkIndexability(live.dom, origin, domRes, postJsFindings, meta, mkSeo, peripherals);
            }, 'seo-jsonld-reconcile', meta);

            const RECONCILE_PREFIXES = ['seo-', 'a11y-', 'slop-', 'img-format', 'inline-scripts', 'deprecated'];
            const isReconciledId = (id) => RECONCILE_PREFIXES.some((p) => String(id).startsWith(p));
            for (let idx = findings.length - 1; idx >= 0; idx--) {
              if (isReconciledId(findings[idx].id)) {
                findings.splice(idx, 1);
              }
            }
            for (const f of postJsFindings) {
              if (!findings.some((x) => x.id === f.id)) findings.push(f);
            }

            // Post-hydration consent reconciliation
            const consentReRender = /cookie[- _]?consent|cookie[ _-]?banner|consent[- _]?management|termly|app\.termly\.io|essential cookies|non-essential cookies|with your consent|preferences.*decline.*accept|klaro|onetrust|cookiebot|cookieyes|complianz|iubenda|didomi|privacy-center\.org|spcloader|usercentrics|sourcepoint|axeptio|borlabs|tarteaucitron|gdpr[- _]?consent|nastavitve piškotkov|cookie-trigger|cookie-modal|gtag\(['"]consent['"]|type=["'](?:didomi\/javascript|text\/plain|text\/consent)/i;
            if (consentReRender.test(live.dom)) {
              for (let idx = findings.length - 1; idx >= 0; idx--) {
                if (findings[idx].id === 'no-consent' || findings[idx].id === 'eu-no-cmp') {
                  findings.splice(idx, 1);
                }
              }
              if (!findings.some((x) => x.id === 'consent-present')) {
                findings.push(makeFinding({
                  id: 'consent-present',
                  domain: 'compliance',
                  severity: 'info',
                  title: 'Consent mechanism detected (post-hydration)',
                  detail: 'A consent pattern (e.g. CMP banner) was detected after client-side hydration. Verify analytics and trackers are actually blocked *before* consent.',
                  fix: 'Test with cookies cleared: no analytics request should fire before the user accepts.',
                }));
              }
            }
          }

          if (!isDomErrorOrBlock) {
            let a11yFindings = [];
            safeRun(() => { a11yFindings = a11y.checkA11yRendered(live.dom, live.contrast, [], meta, mkA11y) || []; }, 'a11y-rendered', meta);
            for (const f of a11yFindings) {
              if (!findings.some((x) => x.id === f.id)) findings.push(f);
            }

            // Post-hydration JS bundle reconciliation
            const renderedScripts = collectScripts(live.dom, origin);
            if (renderedScripts.length > (meta.bundleUrls ? meta.bundleUrls.length : 0)) {
              const bundleFindings = [];
              await checkJsBundles(live.dom, origin, bundleFindings, meta, reqFn);
              for (const f of bundleFindings) {
                if (!findings.some((x) => x.id === f.id)) findings.push(f);
              }
              if (meta.jsBundleText) {
                const probeFindings = [];
                safeRun(() => probes.checkExtendedSecrets(live.dom, meta.jsBundleText, probeFindings, meta, mkProbe), 'secrets-ext-reconcile', meta);
                safeRun(() => probes.checkWebSockets(live.dom, meta.jsBundleText, origin, probeFindings, meta, mkProbe), 'ws-reconcile', meta);
                safeRun(() => probes.checkSupplyChain(live.dom, origin, probeFindings, meta, mkProbe), 'supply-chain-reconcile', meta);
                for (const f of probeFindings) {
                  if (!findings.some((x) => x.id === f.id)) findings.push(f);
                }
              }
            }

            // Tech stack reconciliation from rendered DOM
            const renderedTech = detectTech(res, live.dom);
            if (renderedTech && renderedTech.length) {
              meta.tech = Array.from(new Set([...(meta.tech || []), ...renderedTech]));
            }
          }
          meta.rendered = true;
        } else {
          // P0: the renderer is the thing that keeps perf + rendered-a11y
          // honest. When it is unavailable those domains go empty and the mean
          // score goes *up*. Record it so the report can be capped + flagged.
          deepMeta.performance = { ok: false, error: live.error || 'unavailable' };
          if (res.via !== 'firecrawl') {
            degradedCaps.push(integrity.RENDER_CAPABILITY);
            degradedReasons.push(live.error || 'headless renderer unavailable');
          }
        }
      } catch (e) {
        deepMeta.performance = { ok: false, error: e.message };
        if (res.via !== 'firecrawl') {
          degradedCaps.push(integrity.RENDER_CAPABILITY);
          degradedReasons.push(e.message);
        }
      }
    }

    // (2) Same-origin BFS crawl (skip if root itself is a WAF challenge page).
    let crawl = { origin, pages: [], discovered: 0, pagesScanned: 0 };
    if (meta.isWafChallenge) {
      deepMeta.crawl = { pagesScanned: 0, discovered: 0, skipped: 'waf-challenge' };
      meta.crawledPages = 0;
    } else {
      onProgress && onProgress('crawl', { phaseIdx: 3, msg: 'Pregledujem podstrani spletnega mesta …' });
      crawl = await deep.crawlSite(res.url, reqFn, { maxPages, maxDepth, concurrency: 5 });
      deepMeta.crawl = { pagesScanned: crawl.pagesScanned, discovered: crawl.discovered };

      const pageResults = [];
      const rootNorm = new URL(res.url).toString();
      for (const p of crawl.pages) {
        // Skip the root page — already scanned above (normalise trailing slash).
        let pUrlNorm = p.url;
        let pFinalNorm = p.finalUrl || p.url;
        try { pUrlNorm = new URL(p.url).toString(); } catch (e) {}
        try { pFinalNorm = new URL(p.finalUrl || p.url).toString(); } catch (e) {}
        if (pFinalNorm === rootNorm || pUrlNorm === rootNorm) continue;
        if (p.status !== 200) continue;
        if (isWafChallenge(p, p.body)) continue;
        if (p.headersUnverified || p.via === 'firecrawl' || p.bypassedWaf) {
          if (!meta.headersVerifiedViaChrome) meta.headersUnverified = true;
          if (p.wafProvider && !meta.wafProvider) meta.wafProvider = p.wafProvider;
        }
        const pr = runPageChecks(p, meta);
        if (pr.findings.length) pageResults.push({ url: p.url, findings: pr.findings });
      }

      // Merge crawl findings into the root set (de-duplicated by issue id).
      if (pageResults.length) {
        const merged = mergePageFindings(findings, pageResults);
        findings.length = 0;
        findings.push(...merged);
        meta.crawledPages = crawl.pagesScanned;
        meta.crawlPagesWithFindings = pageResults.length;
      } else {
        meta.crawledPages = crawl.pagesScanned;
      }
    }

    // Re-check legal-policy and EU compliance presence now that we have both
    // the post-JS rendered DOM (`meta.renderBody`) and every crawled page body.
    const allCorpusBodies = [res.body, meta.renderBody, ...crawl.pages.map((p) => p.body)].filter(Boolean);
    meta._policyCorpus = allCorpusBodies;
    checkPolicies(allCorpusBodies, findings, meta);
    safeRun(() => {
      if (!meta.isWafChallenge) {
        const euReconciled = eu.checkEuCompliance(meta.renderBody || res.body, res, findings, meta, peripherals, mkEu);
        for (let idx = findings.length - 1; idx >= 0; idx--) {
          const fid = String(findings[idx].id);
          if (fid.startsWith('eu-') || fid.startsWith('us-') || fid.startsWith('privacy-')) findings.splice(idx, 1);
        }
        for (const f of euReconciled) {
          if (!findings.some((x) => x.id === f.id)) findings.push(f);
        }
      } else {
        for (let idx = findings.length - 1; idx >= 0; idx--) {
          const fid = String(findings[idx].id);
          if (fid.startsWith('eu-') || fid.startsWith('us-') || fid.startsWith('privacy-')) findings.splice(idx, 1);
        }
      }
    }, 'eu-reconcile', meta);
    delete meta._policyCorpus;

    // (3) Optional Firecrawl subpage discovery (only surfaces new URLs).
    if (!skipExternalLookups && process.env.FIRECRAWL_API_KEY) {
      const fc = await deep.firecrawlDiscover(res.url, { limit: 50 });
      deepMeta.firecrawl = fc.ok ? { ok: true, links: (fc.links || []).length } : { ok: false, error: fc.error || fc.reason };
      if (fc.ok && Array.isArray(fc.links) && fc.links.length) {
        const known = new Set(crawl.pages.map((p) => (p.finalUrl || p.url).replace(/#.*$/, '')));
        const extra = fc.links
          .filter((l) => { try { return new URL(l).origin === origin; } catch (e) { return false; } })
          .filter((l) => !known.has(l.replace(/#.*$/, '')))
          .slice(0, 15);
        meta.firecrawlExtraLinks = extra.length;
        if (extra.length) meta.firecrawlLinks = extra.slice(0, 40);
      }
    }

    meta.deep = deepMeta;
  }

  if (!meta.isWafChallenge && (!securityTxt || securityTxt.status !== 200)) {
    findings.push(makeFinding({
      id: 'no-security-txt',
      domain: 'security',
      severity: 'info',
      title: 'No /.well-known/security.txt',
      detail: 'Makes it hard for researchers to report vulnerabilities responsibly.',
      fix: 'Publish security.txt with a contact and expiry.',
    }));
  }

  applyExplain(findings); // attach whatItIs / whoCanAct / impact / worstCase

  // Leaderboard provenance fingerprint (PLAN-LEADERBOARD.md §4).
  try {
    const fpBody = meta.renderBody || res.body;
    meta.build = await buildfp.collect(
      fpBody,
      res,
      options.fingerprint === false ? null : { rawRequest: reqFn }
    );
    if (meta.renderBody) meta.build.usedRenderedDom = true;
    delete meta.renderBody; // never persist the rendered document itself
  } catch (e) {
    meta.build = { error: String(e && e.message ? e.message : e) };
  }

  if (meta.isWafChallenge) {
    degradedCaps.push('waf-intercepted');
    degradedReasons.push(`Target protected by ${meta.wafProvider || 'WAF'} bot challenge (HTTP ${res.status}); content checks suspended`);
    if (!meta.headersHarvested && !degradedCaps.includes(integrity.HEADERS_UNVERIFIED_CAPABILITY)) {
      degradedCaps.push(integrity.HEADERS_UNVERIFIED_CAPABILITY);
    }
  }

  // P0 — if any expected capability was missing, make the report say so *and*
  // add a finding, so a degraded run can never be mistaken for a clean one.
  const degraded = integrity.buildDegraded(degradedCaps, degradedReasons.find(Boolean));
  if (degraded) {
    const f = integrity.degradedFinding(degraded);
    if (f && !findings.some((x) => x.id === f.id)) findings.push(f);
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  onProgress && onProgress('scoring', { phaseIdx: 3, msg: 'Zaključujem analizo in računanje ocene …' });

  const scored = scoreFindings(findings);
  const domains = scoreByDomain(findings);
  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const report = {
    target,
    finalUrl: res.url,
    resolvedIp,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    status: res.status,
    score: scored.score,
    grade: scored.grade,
    // Severity ceiling actually applied (100 = none) — explains the headline score.
    scoreCeiling: scoreCeiling(findings),
    domainAverage: scored.domainScore,
    penalty: scored.penalty,
    domains,
    counts,
    findings,
    meta,
  };

  // P0 — stamp `degraded` and apply the score cap last, after every finding
  // (including the synthetic degraded finding) has been counted.
  integrity.applyDegraded(report, degraded);

  // Hard Invariant Guard: An unverified or WAF-intercepted scan can NEVER
  // masquerade as an A or B grade. Enforce absolute score ceiling.
  if ((meta.isWafChallenge || (degraded && degraded.degraded)) && typeof report.score === 'number' && report.score > (degraded ? degraded.scoreCap : 70)) {
    report.score = degraded ? degraded.scoreCap : 70;
    report.grade = integrity.gradeFor(report.score);
  }

  return report;
}

module.exports = {
  scan,
  rawRequest,
  assertPublicHost,
  checkQuality,
  checkGoogleCrux,
  EXPLAIN,
  EXPLOIT,
  EXPLOIT_STEPS,
  detectTech,
  checkTech,
  checkPolicies,
  egressState,
  scanSecrets,
  detectWaf,
  _promoteChromeHeaders: promoteChromeHeaders,
  _TEST_ALLOW_LOOPBACK: ALLOW_LOOPBACK_TEST,
};

/* ------------------------------------------------------------------ *
 * CLI: node lib/scanner.js https://example.com
 * ------------------------------------------------------------------ */
if (require.main === module) {
  const t = process.argv[2];
  if (!t) {
    console.error('usage: node lib/scanner.js <url>');
    process.exit(1);
  }
  scan(t)
    .then((r) => {
      console.log(JSON.stringify({ target: r.target, score: r.score, grade: r.grade, counts: r.counts, findings: r.findings.map((f) => `[${f.severity}] ${f.title}`) }, null, 2));
    })
    .catch((e) => {
      console.error('scan failed:', e.message);
      process.exit(1);
    });
}
