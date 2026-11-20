'use strict';
/**
 * VibeScan deep-scanning layer — zero external dependencies.
 *
 * Adds three capabilities on top of the single-page engine:
 *   1. crawlSite()        — same-origin BFS crawler (cap pages), re-uses the
 *                           scanner's SSRF-guarded rawRequest for every hop.
 *   2. renderWithHeadless()— renders JS-heavy / SPA pages with headless Chrome
 *                           so client-side content is actually scanned. The
 *                           validated IP is pinned via --host-resolver-rules so
 *                           the browser can't be tricked into hitting a private
 *                           address (SSRF guard parity with the HTTP layer).
 *   3. firecrawlDiscover() — OPTIONAL adapter for the Firecrawl API to discover
 *                           subpages on JS-heavy sites. Dormant unless
 *                           FIRECRAWL_API_KEY is set in the environment.
 */

const { execFile } = require('child_process');
const https = require('https');
const { URL } = require('url');
const egress = require('./egress');        // single source of truth for which exit we use

/* ------------------------------------------------------------------ *
 * 1. Same-origin BFS crawler
 * ------------------------------------------------------------------ */

const ASSET_EXT = /\.(?:png|jpe?g|gif|webp|avif|svg|ico|css|js|mjs|map|woff2?|ttf|otf|eot|mp4|webm|pdf|zip|gz|rar|txt|xml|rss|json)$/i;

function sameOrigin(u, origin) {
  try { return new URL(u, origin).origin === origin; } catch (e) { return false; }
}

// Hard wall-clock ceiling around a single crawl hop. rawRequest has its own
// socket timeout, but a pathological page (huge body, stalled TLS, gzip bomb)
// can still occupy a slot for a long time; this guarantees the batch progresses.
const HOP_TIMEOUT_MS = 15000;
function withTimeout(promise, ms) {
  let timer;
  // Suppress a late rejection from the losing branch so it never becomes an
  // unhandledRejection (the request keeps its own destroy-on-timeout path).
  promise.catch(() => {});
  const guard = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ __timedOut: true }), ms);
  });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

function decodeHtmlAttr(s) {
  return String(s || '')
    .replace(/&amp;/gi, '&')
    .replace(/&#38;/g, '&')
    .replace(/&#x26;/gi, '&');
}

function extractLinks(body, base) {
  const out = new Set();
  const re = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))/gi;
  let m;
  while ((m = re.exec(body))) {
    const rawHref = (m[1] || m[2] || m[3] || '').trim();
    const href = decodeHtmlAttr(rawHref);
    if (!href || /^(?:#|mailto:|tel:|javascript:|data:|blob:)/i.test(href)) continue;
    let u;
    try { u = new URL(href, base); } catch (e) { continue; }
    if (u.origin !== new URL(base).origin) continue;
    u.hash = '';
    if (ASSET_EXT.test(u.pathname)) continue;
    if (u.pathname.startsWith('/cdn-cgi/')) continue;
    out.add(u.toString());
  }
  return [...out];
}

/**
 * Breadth-first crawl, same-origin only, bounded by maxPages + maxDepth.
 * Every fetch goes through the caller-supplied SSRF-guarded rawRequest.
 */
async function crawlSite(startUrl, rawRequest, { maxPages = 25, maxDepth = 2, concurrency = 5 } = {}) {
  const startNorm = new URL(startUrl).toString();
  const origin = new URL(startNorm).origin;
  const seen = new Set([startNorm, startUrl]);
  let frontier = [startNorm];
  const pages = [];
  let depth = 0;

  while (frontier.length && pages.length < maxPages && depth <= maxDepth) {
    const batch = frontier.slice(0, concurrency);
    frontier = frontier.slice(concurrency);

    const results = await Promise.all(batch.map(async (url) => {
      try {
        const r = await withTimeout(Promise.resolve(rawRequest(url, { maxRedirects: 3 })), HOP_TIMEOUT_MS);
        if (r && r.__timedOut) {
          return { url, requested: url, status: 0, error: 'hop timeout after ' + HOP_TIMEOUT_MS + 'ms', headers: {}, body: '' };
        }
        // SECURITY + correctness: rawRequest follows redirects blindly, so a
        // same-origin link can 302 us off-origin — e.g. /api/auth/google bounces
        // to accounts.google.com. Ingesting that page drags the "same-origin"
        // crawl onto massive third-party documents (or, on a hostile target, a
        // private address the redirect guard would otherwise stop). Drop any hop
        // whose FINAL url is no longer same-origin instead of scanning it.
        let finalOrigin = null;
        try { finalOrigin = new URL(r.url).origin; } catch (e) { /* keep null */ }
        if (finalOrigin && finalOrigin !== origin) {
          return { url, requested: url, finalUrl: r.url, status: 0, crossOrigin: true, headers: {}, body: '' };
        }
        return { url, requested: url, finalUrl: r.url, status: r.status, headers: r.headers || {}, body: r.body || '', tls: r.tls, ttfb: r.ttfb };
      } catch (e) {
        return { url, requested: url, status: 0, error: e.message, headers: {}, body: '' };
      }
    }));

    for (const r of results) {
      if (pages.length >= maxPages) break;
      if (!r.body || r.status === 0) continue;
      pages.push(r);
      // Only enqueue further pages for HTML documents.
      const ctype = String(r.headers['content-type'] || '').toLowerCase();
      if (ctype && !ctype.includes('html')) continue;
      for (const link of extractLinks(r.body, r.finalUrl || r.url)) {
        if (seen.has(link)) continue;
        seen.add(link);
        if (frontier.length + pages.length + batch.length < maxPages * 2) frontier.push(link);
      }
    }
    depth++;
  }

  return {
    origin,
    pages,
    discovered: seen.size,
    pagesScanned: pages.length,
  };
}

/* ------------------------------------------------------------------ *
 * 2. Headless rendering (headless Chrome, no npm deps)
 * ------------------------------------------------------------------ */

const CHROME_CANDIDATES = [
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  'google-chrome',
  'google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  'chromium',
  'chromium-browser',
  '/snap/bin/chromium',
];

function pickChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  if (process.env.VIBESCAN_CHROME) return process.env.VIBESCAN_CHROME;
  const fs = require('fs');
  // Resolve each candidate on PATH via the shell, falling back to absolute paths.
  for (const c of CHROME_CANDIDATES) {
    if (c.startsWith('/') && fs.existsSync(c)) return c;
    try {
      const { execSync } = require('child_process');
      const p = execSync(`command -v -- ${c}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (p && fs.existsSync(p)) return p;
    } catch (e) { /* keep looking */ }
  }
  return null;
}

/**
 * Render a URL with headless Chrome and return the post-JS DOM.
 * `resolvedIp` (optional) is pinned so the browser resolves the hostname to the
 * same public IP the SSRF guard already validated.
 */
function renderWithHeadless(targetUrl, resolvedIp, { timeoutMs = 20000, bypassProxy = false } = {}) {
  const chrome = pickChrome();
  if (!chrome) return Promise.resolve({ ok: false, error: 'no headless browser found' });

  let host = '';
  try { host = new URL(targetUrl).hostname; } catch (e) { return Promise.resolve({ ok: false, error: 'bad url' }); }

  const os = require('os');
  const path = require('path');
  const fs = require('fs');
  const profile = path.join(os.tmpdir(), 'vs-spa-' + process.pid + '-' + Date.now());
  try { fs.mkdirSync(profile, { recursive: true }); } catch (e) { /* ignore */ }

  const args = [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-dbus',
    '--disable-extensions',
    '--disable-dev-shm-usage',
    '--user-data-dir=' + profile,
    '--hide-scrollbars',
    '--virtual-time-budget=8000',
    '--dump-dom',
  ];
  const SCANNER_PROXY = egress.chromeProxyFor(host);
  if (SCANNER_PROXY && !bypassProxy) {
    args.push('--proxy-server=' + SCANNER_PROXY);
  } else if (resolvedIp && /^[0-9.]+$/.test(resolvedIp)) {
    // Pin DNS to the validated public IP so the SPA renderer can't SSRF.
    args.push(`--host-resolver-rules=MAP ${host} ${resolvedIp}`);
  }
  args.push(targetUrl);

  return new Promise((resolve) => {
    execFile(chrome, args, {
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
      env: {
        ...process.env,
        HOME: profile,
        XDG_CONFIG_HOME: profile,
        XDG_CACHE_HOME: profile,
      }
    }, (err, stdout) => {
      try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* ignore */ }
      const dom = stdout || '';
      if (err && !dom) return resolve({ ok: false, error: err.message });
      resolve({ ok: dom.length > 0, dom, length: dom.length });
    });
  });
}

/**
 * Heuristic: does the raw HTML look like a client-rendered shell?
 * Returns true when the server HTML is thin (little visible text / mostly a
 * mount node) which strongly implies the real content is injected by JS.
 */
function looksLikeSpa(rawHtml) {
  if (!rawHtml) return true;
  const bodyMatch = rawHtml.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  const body = bodyMatch ? bodyMatch[1] : rawHtml;
  // Strip script/style, then measure visible text.
  const visible = body
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const hasMount = /id\s*=\s*["'](root|app|__next|__nuxt|gatsby-focus-wrapper)["']/i.test(rawHtml);
  return visible.length < 250 || (hasMount && visible.length < 600);
}

/* ------------------------------------------------------------------ *
 * 3. Firecrawl adapter (OPTIONAL, env-gated)
 * ------------------------------------------------------------------ */

function firecrawlDiscover(targetUrl, { timeoutMs = 25000, limit = 50 } = {}) {
  const key = process.env.FIRECRAWL_API_KEY;
  if (!key) return Promise.resolve({ ok: false, skipped: true, reason: 'FIRECRAWL_API_KEY not set' });

  const body = JSON.stringify({ url: targetUrl, limit, includeSubdomains: false });
  return new Promise((resolve) => {
    const req = https.request(
      {
        method: 'POST',
        hostname: 'api.firecrawl.dev',
        path: '/v1/map',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          Authorization: `Bearer ${key}`,
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            resolve({ ok: true, links: data.links || [], success: data.success !== false });
          } catch (e) {
            resolve({ ok: false, error: 'bad Firecrawl response' });
          }
        });
        res.on('error', (e) => resolve({ ok: false, error: e.message }));
      }
    );
    req.on('timeout', () => req.destroy(new Error('Firecrawl timed out')));
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.write(body);
    req.end();
  });
}

module.exports = {
  crawlSite,
  extractLinks,
  renderWithHeadless,
  looksLikeSpa,
  firecrawlDiscover,
  pickChrome,
};
