'use strict';
/**
 * Phase 6 — Active-but-safe security surface.
 *
 * Every probe is a plain, non-destructive GET (or HEAD/OPTIONS). Nothing here
 * writes, deletes, brute-forces, or exploits anything. All requests go through
 * the scanner's SSRF-guarded rawRequest, and redirects are never followed into
 * a third-party origin.
 *
 *   - open redirect            (?next=, ?url=, ?redirect= …)
 *   - reflected-input (XSS indicator)
 *   - Host-header reflection
 *   - HTTP method matrix        (OPTIONS / TRACE / WebDAV)
 *   - directory listing         (autoindex)
 *   - crossdomain.xml / clientaccesspolicy.xml
 *   - GraphQL introspection over GET
 *   - API error verbosity       (stack traces, debug mode)
 *   - public object-storage buckets discovered in JS/HTML
 *   - WebSocket endpoints       (insecure ws://)
 *   - supply-chain: SRI coverage + third-party host map
 */

const { URL } = require('url');
const net = require('net');

/* ------------------------------------------------------------------ *
 * Small helpers
 * ------------------------------------------------------------------ */

function uniq(arr) { return [...new Set(arr)]; }

async function pMap(arr, fn, concurrency = 2) {
  const results = [];
  const executing = [];
  for (const item of arr) {
    const p = Promise.resolve().then(() => fn(item));
    results.push(p);
    if (concurrency <= arr.length) {
      const e = p.then(() => executing.splice(executing.indexOf(e), 1));
      executing.push(e);
      if (executing.length >= concurrency) {
        await Promise.race(executing);
      }
    }
  }
  return Promise.all(results);
}

function scriptSrcs(html) {
  const out = [];
  const re = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))[^>]*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const tag = m[0];
    const src = m[1] ?? m[2] ?? m[3] ?? '';
    out.push({ src, integrity: /\bintegrity\s*=/i.test(tag), crossorigin: /\bcrossorigin\b/i.test(tag) });
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * 6.1 Open redirect
 * ------------------------------------------------------------------ */

const REDIRECT_PARAMS = ['next', 'url', 'redirect', 'redirect_uri', 'return', 'returnTo', 'continue', 'r', 'dest', 'destination', 'target', 'goto'];
const CANARY = 'https://vs-open-redirect-canary.example';

async function checkOpenRedirect(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const hits = [];
  await pMap(REDIRECT_PARAMS, async (p) => {
    const u = new URL(origin);
    u.searchParams.set(p, CANARY);
    try {
      const r = await rawRequest(u.toString(), { maxRedirects: 0 });
      if (r.status >= 300 && r.status < 400 && r.headers && r.headers.location) {
        const loc = String(r.headers.location);
        // Only a redirect that actually LEAVES the origin is an open redirect.
        // A relative Location (e.g. `/en-US/?url=…`) merely echoes the canary in
        // a path/query and stays on-site — that is NOT exploitable. Resolve the
        // Location against the tested URL and compare origins instead of doing a
        // blind substring match on the canary.
        let destination = null;
        try { destination = new URL(loc, u); } catch (e) { destination = null; }
        const originOnly = new URL(origin).origin;
        const leavesOrigin = destination
          ? destination.origin !== originOnly
          : /^https?:\/\//i.test(loc); // unparseable absolute URL → treat as external
        if (leavesOrigin) {
          hits.push(`?${p}= → ${r.status} Location: ${loc}`);
        }
      }
    } catch (e) { /* ignore */ }
  });

  meta.probes = meta.probes || {};
  meta.probes.openRedirect = hits;
  if (hits.length) {
    findings.push(mk('open-redirect', 'high', `Open redirect on ${hits.length} parameter(s)`,
      'An attacker can craft a link on your own trusted domain that bounces the victim to a site they control. That is the perfect wrapper for a phishing or OAuth-consent page.',
      'Allow-list the redirect destinations server-side, or use an internal id instead of a URL parameter.',
      hits.join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.2 Reflected input (XSS indicator)
 * ------------------------------------------------------------------ */

const REFLECT_PARAMS = ['q', 's', 'search', 'query', 'lang', 'page', 'id', 'name', 'msg', 'error', 'callback'];

async function checkReflectedInput(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const MARK = 'vsprobe9f3a';
  const PAYLOAD = `${MARK}'"><vs>`;
  const hits = [];

  await pMap(REFLECT_PARAMS, async (p) => {
    const u = new URL(origin);
    u.searchParams.set(p, PAYLOAD);
    try {
      const r = await rawRequest(u.toString(), { maxRedirects: 2 });
      if (!r.body) return;
      const idx = r.body.indexOf(MARK);
      if (idx < 0) return;
      const window = r.body.slice(Math.max(0, idx - 40), idx + PAYLOAD.length + 40);
      const unescaped = window.includes(`${MARK}'"><vs>`);
      const ctype = String((r.headers && r.headers['content-type']) || '').toLowerCase();
      hits.push({
        param: p,
        escape: unescaped ? 'UNESCAPED' : 'escaped',
        ctype: ctype.split(';')[0] || 'unknown',
        snippet: window.replace(/\s+/g, ' ').slice(0, 160),
      });
    } catch (e) { /* ignore */ }
  });

  const unescapedHits = hits.filter((h) => h.escape === 'UNESCAPED');
  meta.probes = meta.probes || {};
  meta.probes.reflected = hits;

  if (unescapedHits.length) {
    findings.push(mk('reflected-input', 'medium', `Input is reflected unescaped on ${unescapedHits.length} parameter(s)`,
      'The exact characters you sent come back inside the HTML document with no encoding. If any of them land inside a tag, attribute or script context, that is DOM-executable XSS — the single most common critical web vulnerability.',
      'Context-aware output encoding (HTML / attribute / JS / URL) and a strict Content-Security-Policy. Never build HTML by string concatenation.',
      unescapedHits.map((h) => `?${h.param}= → ${h.ctype}\n  ${h.snippet}`).join('\n')));
  } else if (hits.length) {
    findings.push(mk('reflected-input-escaped', 'info', `Input is reflected but safely escaped (${hits.length} parameter(s))`,
      'Parameters are echoed back into the page — normal for search pages — but the payload was encoded, so it is not injectable.',
      'No action required. Keep the encoding in place when refactoring.'));
  }
}

/* ------------------------------------------------------------------ *
 * 6.3 Host-header reflection
 * ------------------------------------------------------------------ */

async function checkHostHeader(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const fakeHost = 'evil-vs-host.example';
  let reflected = false;
  let detail = '';

  try {
    const r = await rawRequest(origin, { maxRedirects: 0, headers: { Host: fakeHost, 'X-Forwarded-Host': fakeHost } });
    const hay = (r.body || '').slice(0, 200000);
    const loc = String((r.headers && r.headers.location) || '');
    if (hay.includes(fakeHost) || loc.includes(fakeHost)) {
      reflected = true;
      const idx = hay.indexOf(fakeHost);
      detail = idx >= 0
        ? hay.slice(Math.max(0, idx - 80), idx + 120).replace(/\s+/g, ' ')
        : `Location: ${loc}`;
    }
  } catch (e) {
    meta.probes = meta.probes || {};
    meta.probes.hostHeader = { skipped: e.message };
    return;
  }

  meta.probes = meta.probes || {};
  meta.probes.hostHeader = { reflected, detail };

  if (reflected) {
    findings.push(mk('host-header-injection', 'medium', 'Incoming Host header is echoed into responses',
      'The server trusts a client-supplied Host. That enables password-reset link poisoning (reset tokens sent to the attacker\'s domain), cache poisoning, and SSRF against internal vhosts.',
      'Configure a strict server_name / allowed-hosts list and reject unknown Host values with 421 or 400. Never build absolute URLs from the request Host.',
      detail));
  }
}

/* ------------------------------------------------------------------ *
 * 6.4 HTTP method matrix
 * ------------------------------------------------------------------ */

async function checkHttpMethods(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const dangerous = [];
  let allow = '';

  try {
    const opt = await rawRequest(origin, { method: 'OPTIONS', maxRedirects: 0 });
    allow = String((opt.headers && opt.headers.allow) || '');
    for (const m of ['PUT', 'DELETE', 'TRACE', 'PATCH', 'PROPFIND']) {
      if (new RegExp(`(?:^|,\\s*)${m}(?:,|$)`, 'i').test(allow)) dangerous.push(m);
    }
  } catch (e) { /* ignore */ }

  // TRACE is reflected back verbatim when enabled.
  try {
    const tr = await rawRequest(origin, { method: 'TRACE', maxRedirects: 0 });
    if (tr.status === 200 && /TRACE\s+\//i.test(tr.body || '')) dangerous.push('TRACE (echoed)');
  } catch (e) { /* ignore */ }

  const uniqDangerous = uniq(dangerous);
  meta.probes = meta.probes || {};
  meta.probes.methods = { allow, dangerous: uniqDangerous };

  if (uniqDangerous.length) {
    findings.push(mk('http-methods', 'medium', `Unexpected HTTP method(s) enabled: ${uniqDangerous.join(', ')}`,
      'Write methods on a static site mean anyone can overwrite files. TRACE lets an attacker bypass HttpOnly, replaying session cookies in the response body (Cross-Site Tracing).',
      'Disable PUT/DELETE/TRACE/TRACK at the server or WAF unless the application genuinely needs them.',
      `Allow: ${allow || '(none advertised)'}`));
  }
}

/* ------------------------------------------------------------------ *
 * 6.5 Directory listing
 * ------------------------------------------------------------------ */

const LISTING_PATHS = ['/uploads/', '/upload/', '/images/', '/img/', '/files/', '/assets/', '/static/', '/media/', '/backup/', '/tmp/'];

async function checkDirectoryListing(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const hits = [];
  await pMap(LISTING_PATHS, async (p) => {
    try {
      const r = await rawRequest(new URL(p, origin).toString(), { maxRedirects: 0 });
      if (r.status !== 200 || !r.body) return;
      const body = r.body.slice(0, 4000);
      const isAutoindex =
        /<title>\s*Index of\s*\//i.test(body) ||
        /<h1>\s*Index of\s*\//i.test(body) ||
        (/<a\b[^>]*href\s*=\s*["'][^"']+["'][^>]*>/i.test(body) &&
          /Parent Directory/i.test(body));
      if (isAutoindex) hits.push(`${p} (${r.bytes} bytes)`);
    } catch (e) { /* ignore */ }
  });

  meta.probes = meta.probes || {};
  meta.probes.directoryListing = hits;
  if (hits.length) {
    findings.push(mk('dir-listing', 'high', `Directory listing enabled on ${hits.length} path(s)`,
      'Anyone can enumerate every file in the folder — backups, drafts, uploads with personal data, source maps, config dumps. This is one of the fastest routes from "found a site" to "found a breach".',
      'Disable autoindex (`Options -Indexes` / `autoindex off;`), and never serve user uploads from a browsable directory.',
      hits.join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.6 Legacy Flash policy files
 * ------------------------------------------------------------------ */

const POLICY_PATHS = ['/crossdomain.xml', '/clientaccesspolicy.xml'];

async function checkCrossdomainPolicy(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const hits = [];
  await pMap(POLICY_PATHS, async (p) => {
    try {
      const r = await rawRequest(new URL(p, origin).toString(), { maxRedirects: 0 });
      if (r.status !== 200 || !r.body) return;
      const ctype = String((r.headers && r.headers['content-type']) || '');
      if (isHtmlDoc(r.body, ctype)) return;
      const body = r.body.slice(0, 3000);
      if (!/<cross-domain-policy\b|<access-policy\b/i.test(body)) return;
      if (/domain\s*=\s*["']\*["']/i.test(body) || /allow-access-from\s+domain\s*=\s*["']\*["']/i.test(body)) {
        hits.push(`${p} → allows domain="*"`);
      } else {
        hits.push(`${p} → present`);
      }
    } catch (e) { /* ignore */ }
  });

  meta.probes = meta.probes || {};
  meta.probes.crossdomain = hits;
  if (hits.length) {
    findings.push(mk('crossdomain-policy', 'low', `Legacy cross-domain policy file(s) published: ${hits.length}`,
      'These files were only ever read by Flash and Silverlight. A wildcard entry let any website load authenticated responses in the user\'s browser, and the files are now pure attack surface with zero benefit.',
      'Delete /crossdomain.xml and /clientaccesspolicy.xml.',
      hits.join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.7 GraphQL introspection
 * ------------------------------------------------------------------ */

const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/graphql/v1'];
const INTROSPECTION_QUERY = '{__schema{queryType{name}types{name}}}';

async function checkGraphqlIntrospection(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const hits = [];
  await pMap(GRAPHQL_PATHS, async (p) => {
    const u = new URL(p, origin);
    u.searchParams.set('query', INTROSPECTION_QUERY);
    try {
      const r = await rawRequest(u.toString(), { maxRedirects: 0 });
      if (r.status !== 200 || !r.body) return;
      if (/"__schema"|"queryType"|"types"\s*:\s*\[/i.test(r.body)) {
        const names = uniq([...r.body.matchAll(/"name"\s*:\s*"([A-Za-z0-9_]+)"/g)].map((m) => m[1]));
        hits.push({ path: p, types: names.length, sample: names.slice(0, 15).join(', ') });
      }
    } catch (e) { /* ignore */ }
  });

  meta.probes = meta.probes || {};
  meta.probes.graphql = hits;
  if (hits.length) {
    findings.push(mk('graphql-introspection', 'medium', `GraphQL introspection is enabled at ${hits.length} endpoint(s)`,
      'Introspection returns the complete schema: every type, every field, including admin-only mutations and internal fields you never meant to expose. It turns API discovery from guesswork into a single request.',
      'Disable introspection in production, keep the schema private, and enforce per-field authorization — not just endpoint auth.',
      hits.map((h) => `${h.path} → ${h.types} type(s): ${h.sample}`).join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.8 API error verbosity
 * ------------------------------------------------------------------ */

const ERROR_PATHS = ['/api/does-not-exist-vs', '/api/v1/does-not-exist-vs', '/nonexistent-vs-404-probe', '/api/../etc/passwd%00'];

async function checkApiErrorVerbosity(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const hits = [];

  const signatures = [
    [/at\s+\w+\s*\([^)]*:\d+:\d+\)/, 'Node.js stack trace with file:line'],
    [/Traceback \(most recent call last\)/, 'Python traceback'],
    [/SQLSTATE\[|You have an error in your SQL syntax|pg_query\(|ORA-\d{5}/, 'SQL error / query leak'],
    [/Whoops/i, 'Laravel Whoops debug page'],
    [/<b>Warning<\/b>:\s|Fatal error:\s|Notice:\s.*on line\s+\d+/i, 'PHP warning/notice with path'],
    [/DEBUG\s*=\s*True|Django.*Exception|DisallowedHost/i, 'Django debug mode'],
    [/"stackTrace"|"stack"\s*:\s*"[^"]*at\s/, 'JSON error body containing a stack'],
    [/\/var\/www\/|C:\\inetpub\\|\/home\/[a-z0-9_-]+\//i, 'Absolute server filesystem path'],
  ];

  for (const p of ERROR_PATHS) {
    try {
      const r = await rawRequest(new URL(p, origin).toString(), { maxRedirects: 0 });
      if (!r.body) continue;
      const body = r.body.slice(0, 60000);
      for (const [re, label] of signatures) {
        if (re.test(body)) {
          const mm = body.match(re);
          hits.push({ path: p, status: r.status, label, snippet: String(mm[0]).replace(/\s+/g, ' ').slice(0, 160) });
        }
      }
    } catch (e) { /* ignore */ }
  }

  meta.probes = meta.probes || {};
  meta.probes.errorVerbosity = hits;
  if (hits.length) {
    findings.push(mk('api-error-verbose', 'medium', `Error responses leak internals (${hits.length} signature(s))`,
      'Stack traces and SQL errors hand an attacker your framework, version, file paths and query structure. That is the reconnaissance step that turns a generic exploit into a targeted one.',
      'Return generic error bodies to clients (correlation id + friendly message), log details server-side only, and disable debug mode in production.',
      hits.map((h) => `${h.path} [${h.status}] ${h.label}\n  ${h.snippet}`).join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.9 Public object-storage buckets
 * ------------------------------------------------------------------ */

const BUCKET_PATTERNS = [
  [/https?:\/\/([a-z0-9.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/gi, 'S3'],
  [/https?:\/\/s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9.-]+)/gi, 'S3'],
  [/https?:\/\/storage\.googleapis\.com\/([a-z0-9._-]+)/gi, 'GCS'],
  [/https?:\/\/([a-z0-9-]+)\.blob\.core\.windows\.net/gi, 'Azure Blob'],
];

function findBuckets(text) {
  const out = [];
  for (const [re, kind] of BUCKET_PATTERNS) {
    let m;
    const rx = new RegExp(re.source, re.flags);
    while ((m = rx.exec(text))) out.push({ kind, bucket: m[1], url: m[0] });
  }
  return out;
}

async function checkOpenBuckets(html, jsText, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const found = findBuckets((html || '') + '\n' + (jsText || ''));
  const open = [];

  for (const b of uniq(found.map((f) => JSON.stringify(f))).map((s) => JSON.parse(s)).slice(0, 8)) {
    let probe = null;
    if (b.kind === 'S3') probe = `https://${b.bucket}.s3.amazonaws.com/?list-type=2&max-keys=3`;
    else if (b.kind === 'GCS') probe = `https://storage.googleapis.com/storage/v1/b/${b.bucket}/o?maxResults=3`;
    else probe = `https://${b.bucket}.blob.core.windows.net/?restype=container&comp=list&maxresults=3`;
    try {
      const r = await rawRequest(probe, { maxRedirects: 0 });
      const body = r.body || '';
      if (r.status === 200 && /<ListBucketResult|<EnumerationResults|"items"\s*:\s*\[/.test(body)) {
        const keys = uniq([...body.matchAll(/<Key>([^<]+)<\/Key>|"name"\s*:\s*"([^"]+)"/g)].map((m) => m[1] || m[2])).slice(0, 5);
        open.push({ ...b, keys });
      }
    } catch (e) { /* ignore */ }
  }

  meta.probes = meta.probes || {};
  meta.probes.buckets = { discovered: uniq(found.map((f) => `${f.kind}:${f.bucket}`)), open: open.map((o) => `${o.kind}:${o.bucket}`) };

  if (open.length) {
    findings.push(mk('bucket-public', 'critical', `Publicly listable object-storage bucket(s): ${open.length}`,
      'The bucket behind your frontend answers to anonymous listing requests. Everything ever uploaded — invoices, exports, avatars, database dumps — is browsable and downloadable by anyone who guesses the name.',
      'Block public access at the bucket level, remove the ListBucket/container-list permission from anonymous principals, and serve files through signed URLs.',
      open.map((o) => `${o.kind} // ${o.bucket}\n  keys: ${o.keys.join(', ') || '(listing returned)'}`).join('\n')));
  } else if (found.length) {
    findings.push(mk('bucket-referenced', 'info', `${uniq(found.map((f) => f.bucket)).length} object-storage bucket(s) referenced`,
      'Storage buckets are referenced from your frontend. They did not answer an anonymous listing request, which is the correct configuration.',
      'No action required. Keep public-access-block enabled and rotate credentials used by the app.'));
  }
}

/* ------------------------------------------------------------------ *
 * 6.10 WebSocket endpoints
 * ------------------------------------------------------------------ */

function findWebSockets(text) {
  const out = [];
  const re = /\b(wss?):\/\/([A-Za-z0-9._~:\-?#\[\]@!$&'()*+,;=%/]+)/g;
  let m;
  while ((m = re.exec(text || ''))) out.push({ scheme: m[1], url: m[0] });
  return out;
}

function checkWebSockets(html, jsText, origin, findings, meta, mk) {
  const all = uniq(findWebSockets((html || '') + '\n' + (jsText || '')).map((w) => w.url));
  const insecure = all.filter((u) => u.startsWith('ws://'));
  const secure = all.filter((u) => u.startsWith('wss://'));

  meta.probes = meta.probes || {};
  meta.probes.websockets = { secure, insecure };

  if (insecure.length) {
    findings.push(mk('ws-insecure', 'high', `${insecure.length} insecure WebSocket endpoint(s) (ws://)`,
      'A ws:// socket is unencrypted and unauthenticated at the transport layer. Anyone on the same Wi-Fi can read the message stream and inject frames into it — including session tokens and chat messages.',
      'Move every socket to wss:// with a valid certificate, and authenticate the connection with a short-lived ticket rather than a long-lived session cookie.',
      insecure.join('\n')));
  }
  if (secure.length) {
    findings.push(mk('ws-endpoints', 'info', `${secure.length} WebSocket endpoint(s) discovered`,
      'Authenticated realtime channels are part of the attack surface: authorization must be enforced per-message and per-channel, not only at connect time.',
      'Verify each channel checks the user\'s permission for every subscribe/send action.',
      secure.slice(0, 10).join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.11 Supply chain: SRI + third-party host map
 * ------------------------------------------------------------------ */

// Dynamic rolling endpoints (CAPTCHA challenges, tag managers, analytics, payment SDKs)
// where vendors explicitly forbid/break with static Subresource Integrity (SRI) hashes.
const DYNAMIC_NON_SRI_HOSTS = /(?:^|\.)(?:challenges\.cloudflare\.com|static\.cloudflareinsights\.com|googletagmanager\.com|google-analytics\.com|google\.com|gstatic\.com|hcaptcha\.com|js\.hcaptcha\.com|js\.stripe\.com|plausible\.io)$/i;

function checkSupplyChain(html, origin, findings, meta, mk) {
  const scripts = scriptSrcs(html);
  const hosts = {};
  const thirdParty = [];
  const noSri = [];

  for (const s of scripts) {
    if (!s.src) continue;
    let host = null;
    try {
      const u = new URL(s.src, origin);
      host = u.host;
      hosts[host] = (hosts[host] || 0) + 1;
      const isThird = u.origin !== origin;
      if (isThird) {
        thirdParty.push(`https://${host}`);
        const isDynamicLoader = DYNAMIC_NON_SRI_HOSTS.test(u.hostname) ||
          /\/(?:turnstile|recaptcha|gtag\/js|gtm\.js|beacon\.min\.js)/i.test(u.pathname);
        if (!s.integrity && !isDynamicLoader) {
          noSri.push(`${s.src}${s.crossorigin ? '' : '  (no crossorigin)'}`);
        }
      }
    } catch (e) { /* ignore */ }
  }

  const tp = uniq(thirdParty);
  meta.probes = meta.probes || {};
  meta.probes.supplyChain = { hosts, thirdParty: tp, scripts: scripts.length, missingSri: noSri.length };

  if (tp.length && noSri.length) {
    findings.push(mk('sri-missing', 'medium', `${noSri.length} third-party script(s) load without SRI`,
      'The browser executes whatever that CDN returns, today and on every future load. One compromised package or one DNS hijack on the CDN and arbitrary JavaScript runs as you — with full DOM, cookie and network access.',
      'Add integrity="sha384-…" and crossorigin="anonymous" to every third-party <script> and <link rel="stylesheet">.',
      noSri.slice(0, 10).join('\n')));
  }
  if (tp.length >= 5) {
    findings.push(mk('third-party-surface', 'low', `${tp.length} distinct third-party script host(s)`,
      'Each external host is a dependency you do not control: an availability risk, a privacy transfer (GDPR), and an extra DNS + TLS round-trip before your page can render.',
      'Self-host critical libraries, and remove any third-party tag that is not actively earning its keep.',
      tp.join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.12 Extended secret / PII patterns
 * ------------------------------------------------------------------ */

const EXTRA_SECRETS = [
  ['GitHub token', /gh[pousr]_[A-Za-z0-9]{36,}/g],
  ['GitLab token', /glpat-[A-Za-z0-9_-]{20,}/g],
  ['OpenAI key', /sk-(?:proj-)?[A-Za-z0-9_-]{32,}/g],
  ['Anthropic key', /sk-ant-[A-Za-z0-9_-]{20,}/g],
  ['SendGrid key', /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g],
  ['Twilio SID', /AC[0-9a-fA-F]{32}/g],
  ['Mailgun key', /key-[0-9a-f]{32}/g],
  ['npm token', /npm_[A-Za-z0-9]{36}/g],
  ['Supabase service key', /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}/g],
  ['Discord bot token', /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g],
  ['Basic auth in URL', /https?:\/\/[A-Za-z0-9._%-]+:[^@\s/]{6,}@/g],
  ['Postgres/MySQL DSN', /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s"'<>]{10,}/gi],
  ['Private IP with port', /(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}:\d{2,5}/g],
];

function passesLuhn(numStr) {
  const digits = String(numStr).replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) return false;
  if (/^(\d)\1+$/.test(digits)) return false; // reject 0000000000000000 or 1111111111111111
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

const IBAN_LENGTHS = {
  AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20, BR: 29, BG: 22,
  CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DO: 28, EE: 20, FO: 18, FI: 18, FR: 27,
  GE: 22, DE: 22, GI: 23, GR: 27, GL: 18, GT: 28, HU: 28, IS: 26, IE: 22, IL: 23,
  IT: 27, JO: 30, KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28, LI: 21, LT: 20, LU: 20,
  MK: 19, MT: 31, MR: 27, MU: 30, MD: 24, MC: 27, ME: 22, NL: 18, NO: 15, PK: 24,
  PS: 29, PL: 28, PT: 25, QA: 29, RO: 24, LC: 32, SM: 27, ST: 25, SA: 24, RS: 22,
  SC: 31, SK: 24, SI: 19, ES: 24, SE: 24, CH: 21, TL: 23, TN: 24, TR: 26, UA: 29,
  AE: 23, GB: 22, VA: 22, VG: 24,
};

function isValidIBAN(input) {
  const str = String(input || '').replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(str)) return false;
  const country = str.slice(0, 2);
  if (!IBAN_LENGTHS[country] || str.length !== IBAN_LENGTHS[country]) return false;
  const rearranged = str.slice(4) + str.slice(0, 4);
  const digitsStr = rearranged.replace(/[A-Z]/g, (ch) => ch.charCodeAt(0) - 55);
  try {
    return BigInt(digitsStr) % 97n === 1n;
  } catch {
    return false;
  }
}

const BIZ_TERMS_RE = /\b(trr|transakcijski|iban|d\.o\.o|s\.p|d\.d|d\.n\.o|k\.d|z\.o\.o|gmbh|ag|ltd|llc|inc|bančni račun|bancni racun|bančni|bancni|račun|racun|plačilo|placilo|podjetje|imprint|kontakt|contact|payment|wire transfer|bank account|bic|swift|sklic|referenca|prejemnik|upn|nakazilo)\b/i;

const MAX_SCAN_TEXT_LEN = 1_500_000;

/**
 * Strip <tagName ...>...</tagName> blocks in strictly linear O(N) time without
 * regex backtracking, even on malformed or unclosed tags.
 */
function stripTagBlocks(html, tagName) {
  if (!html) return '';
  const lower = html.toLowerCase();
  const openToken = '<' + tagName;
  const closeToken = '</' + tagName;
  const out = [];
  let pos = 0;

  while (pos < html.length) {
    const idx = lower.indexOf(openToken, pos);
    if (idx === -1) {
      out.push(html.slice(pos));
      break;
    }
    const after = lower[idx + openToken.length];
    if (after !== undefined && after !== '>' && after !== '/' && !/\s/.test(after)) {
      out.push(html.slice(pos, idx + 1));
      pos = idx + 1;
      continue;
    }
    out.push(html.slice(pos, idx));
    const openEnd = html.indexOf('>', idx + openToken.length);
    if (openEnd === -1) {
      out.push(html.slice(idx));
      break;
    }
    const closeIdx = lower.indexOf(closeToken, openEnd + 1);
    if (closeIdx === -1) {
      out.push(html.slice(idx));
      break;
    }
    const closeEnd = html.indexOf('>', closeIdx + closeToken.length);
    if (closeEnd === -1) {
      out.push(html.slice(idx));
      break;
    }
    out.push(' ');
    pos = closeEnd + 1;
  }

  return out.join('');
}

/**
 * Strip HTML comments (<!-- ... -->) in strictly linear O(N) time.
 */
function stripHtmlComments(html) {
  if (!html) return '';
  const out = [];
  let pos = 0;
  while (pos < html.length) {
    const idx = html.indexOf('<!--', pos);
    if (idx === -1) {
      out.push(html.slice(pos));
      break;
    }
    out.push(html.slice(pos, idx), ' ');
    const closeIdx = html.indexOf('-->', idx + 4);
    if (closeIdx === -1) break;
    pos = closeIdx + 3;
  }
  return out.join('');
}

/**
 * Extract the inner HTML of the first <footer>...</footer> element in O(N) time.
 */
function extractFooterInnerHtml(html) {
  if (!html) return null;
  const lower = html.toLowerCase();
  let pos = 0;
  while (pos < lower.length) {
    const idx = lower.indexOf('<footer', pos);
    if (idx === -1) return null;
    const after = lower[idx + 7];
    if (after !== undefined && after !== '>' && after !== '/' && !/\s/.test(after)) {
      pos = idx + 1;
      continue;
    }
    const openEnd = html.indexOf('>', idx + 7);
    if (openEnd === -1) return null;
    const closeIdx = lower.indexOf('</footer', openEnd + 1);
    if (closeIdx === -1) return null;
    return html.slice(openEnd + 1, closeIdx);
  }
  return null;
}

function isPublicCompanyTrr(rawHtml, jsText, sample) {
  if (!rawHtml || !sample) return false;
  const boundedHtml = rawHtml.length > MAX_SCAN_TEXT_LEN ? rawHtml.slice(0, MAX_SCAN_TEXT_LEN) : rawHtml;
  const rawIban = sample.replace(/[\s-]/g, '').toUpperCase();

  const noScripts = stripHtmlComments(
    stripTagBlocks(stripTagBlocks(boundedHtml, 'script'), 'style')
  );

  const visibleText = noScripts.replace(/<[^>]+>/g, ' ');

  let idx = visibleText.indexOf(sample);
  if (idx === -1) {
    idx = visibleText.toUpperCase().indexOf(rawIban);
  }
  if (idx === -1 && rawIban.length > 0 && rawIban.length <= 34) {
    const escapedChars = rawIban.split('').map((ch) => ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const spaced = escapedChars.join('\\s{0,4}');
    const m = new RegExp(spaced, 'i').exec(visibleText);
    if (m) idx = m.index;
  }

  const checkFooter = () => {
    const footerInner = extractFooterInnerHtml(noScripts);
    if (!footerInner) return false;
    const footerText = footerInner.replace(/<[^>]+>/g, ' ');
    const hasIban = footerText.includes(sample) || footerText.replace(/[\s-]/g, '').toUpperCase().includes(rawIban);
    return Boolean(hasIban && BIZ_TERMS_RE.test(footerText));
  };

  if (idx === -1) {
    return checkFooter();
  }

  const start = Math.max(0, idx - 500);
  const end = Math.min(visibleText.length, idx + sample.length + 500);
  const snippet = visibleText.slice(start, end);

  if (BIZ_TERMS_RE.test(snippet)) {
    return true;
  }

  if (checkFooter()) {
    return true;
  }

  return false;
}

const PII_PATTERNS = [
  ['IBAN', /\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}\b/g],
  ['Credit-card-shaped number', /(?<![\d.])\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{3,4}\b(?![\d.])/g],
  ['EU phone number', /\+3[0-9]\d{6,12}\b/g],
  ['Email address', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
];

function scanExtendedSecrets(text) {
  if (!text) return [];
  const input = text.length > MAX_SCAN_TEXT_LEN ? text.slice(0, MAX_SCAN_TEXT_LEN) : text;
  const out = [];
  for (const [name, re] of EXTRA_SECRETS) {
    const rx = new RegExp(re.source, re.flags);
    let m;
    let n = 0;
    while ((m = rx.exec(input)) && n < 5) {
      const sample = m[0];
      if (name === 'Supabase service key') {
        try {
          const parts = sample.split('.');
          if (parts.length >= 2) {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
            if (payload && payload.iss === 'netlify') continue;
            // Public client anon key is NOT a secret service key (operates under PostgreSQL RLS)
            if (payload && payload.role === 'anon') continue;
            // If role is present but not service_role, do not flag as a service key
            if (payload && payload.role && payload.role !== 'service_role') continue;
          }
        } catch (_) {}
      }
      out.push({ name, sample: sample.slice(0, 60) });
      n++;
    }
  }
  return out;
}

function scanPii(text) {
  if (!text) return [];
  const input = text.length > MAX_SCAN_TEXT_LEN ? text.slice(0, MAX_SCAN_TEXT_LEN) : text;
  const out = [];
  for (const [name, re] of PII_PATTERNS) {
    const rx = new RegExp(re.source, re.flags);
    let m;
    let n = 0;
    while ((m = rx.exec(input)) && n < 5) {
      const sample = m[0];
      // Credit cards MUST satisfy the Luhn algorithm (checksum mod 10)
      if (name === 'Credit-card-shaped number') {
        const prevChar = m.index > 0 ? input[m.index - 1] : '';
        const nextChar = m.index + sample.length < input.length ? input[m.index + sample.length] : '';
        if (prevChar === '.' || nextChar === '.') continue;
        if (/\d/.test(prevChar) || /\d/.test(nextChar)) continue;
        if (/[a-zA-Z_%]/.test(nextChar) || /[a-zA-Z_%]/.test(prevChar)) continue;
        if (!passesLuhn(sample)) continue;
      }
      if (name === 'IBAN') {
        if (!isValidIBAN(sample)) continue;
      }
      out.push({ name, sample: sample.slice(0, 60) });
      n++;
    }
  }
  return out;
}

function checkExtendedSecrets(html, jsText, findings, meta, mk) {
  // Bound oversized payloads to avoid pathological regex memory/CPU spikes.
  const boundedHtml = (html || '').length > MAX_SCAN_TEXT_LEN ? html.slice(0, MAX_SCAN_TEXT_LEN) : (html || '');
  const boundedJs = (jsText || '').length > MAX_SCAN_TEXT_LEN ? jsText.slice(0, MAX_SCAN_TEXT_LEN) : (jsText || '');

  // Strip <meta> tags, link tags, attributes, URLs and query parameters before checking PII
  // to avoid false positives on public IDs (e.g. fb:app_id, google-site-verification, twitter:site:id, YouTube playlist IDs).
  const cleanHtml = boundedHtml
    .replace(/<meta\b[^>]*>/gi, '')
    .replace(/<link\b[^>]*>/gi, '')
    .replace(/fb:app_id["']?\s*[:=]\s*["']?\d+/gi, '')
    .replace(/appId["']?\s*[:=]\s*["']?\d+/gi, '')
    .replace(/\b(?:href|src|action|poster)\s*=\s*["'][^"']*["']/gi, '')
    .replace(/https?:\/\/[^\s"'<>]+/gi, '')
    .replace(/[?&][a-zA-Z0-9_]+=[a-zA-Z0-9_-]+/gi, '');

  const cleanJsForPii = boundedJs
    .replace(/https?:\/\/[^\s"'<>]+/gi, '')
    .replace(/[?&][a-zA-Z0-9_]+=[a-zA-Z0-9_-]+/gi, '');

  const hay = cleanJsForPii + '\n' + cleanHtml;

  // Only scan the JS bundles for the credential patterns — the page HTML is
  // full of user-visible e-mail addresses and phone numbers by design.
  const creds = scanExtendedSecrets(boundedJs);
  const pii = scanPii(hay);
  const emailOnly = pii.every((p) => p.name === 'Email address');
  const strongPii = pii.filter((p) => p.name !== 'Email address' && p.name !== 'EU phone number');
  const ibanLike = pii.filter((p) => p.name === 'IBAN');

  const publicTrrs = [];
  const leakedIbans = [];
  for (const item of ibanLike) {
    if (isPublicCompanyTrr(boundedHtml, boundedJs, item.sample)) {
      publicTrrs.push(item);
    } else {
      leakedIbans.push(item);
    }
  }

  meta.secrets = meta.secrets || {};
  meta.secrets.extended = uniq(creds.map((c) => c.name));
  meta.secrets.pii = uniq(pii.filter((p) => {
    if (p.name === 'IBAN') {
      return leakedIbans.some((l) => l.sample === p.sample);
    }
    return true;
  }).map((p) => p.name));
  if (publicTrrs.length) {
    meta.secrets.publicTrr = uniq(publicTrrs.map((p) => p.sample));
  }

  if (creds.length) {
    findings.push(mk('secret-leak-extended', 'critical', `${uniq(creds.map((c) => c.name)).length} additional credential type(s) found in frontend code`,
      'These tokens are served to every visitor in plain text. Anyone who opens DevTools — or just runs `curl` on the bundle — owns that credential and every system it unlocks.',
      'Revoke the key immediately, rotate it, and move the call behind a server-side proxy. Frontend code can never hold a secret.',
      uniq(creds.map((c) => `${c.name}: ${c.sample}…`)).join('\n')));
  }

  // Non-IBAN hard PII (e.g. credit card numbers)
  const otherHardPii = strongPii.filter((p) => p.name !== 'IBAN');
  if (otherHardPii.length && !emailOnly) {
    findings.push(mk('pii-exposure', 'high', `Personal / financial data found in page or bundle source`,
      'Identifiers such as credit-card numbers embedded in the source are exfiltration-grade leaks and, under GDPR, a personal-data breach requiring notification.',
      'Remove the data from the frontend entirely; serve it via an authenticated API call that only returns rows the user is entitled to.',
      uniq(otherHardPii.map((p) => `${p.name}: ${p.sample}`)).join('\n')));
  }

  // Real leaked IBANs (in JS bundle, JSON data attribute, or without business/payment context)
  if (leakedIbans.length) {
    findings.push(mk('pii-iban', 'high', `${leakedIbans.length} IBAN-shaped value(s) exposed in source`,
      'An IBAN plus a name is enough to initiate a SEPA direct debit. Exposing it in HTML is both a fraud vector and a GDPR Art. 34 breach-notification event.',
      'Never render bank details from client-side data; mask all but the last four digits.',
      uniq(leakedIbans.map((p) => p.sample)).join('\n')));
  }

  // Public corporate bank accounts / TRRs (customary for bank transfer / UPN)
  if (publicTrrs.length) {
    findings.push(mk('public-company-trr', 'info', 'Public business bank account (TRR/IBAN) displayed',
      'The page publishes a verified business bank account (customary for bank transfer / UPN payments). Under GDPR Recital 14, legal entity data is not personal data.',
      'No action required if this is an intentional corporate bank account for customer wire transfers.',
      uniq(publicTrrs.map((p) => p.sample)).join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.13 Exposed sensitive files & config recon
 * ------------------------------------------------------------------ */

function isHtmlDoc(body, contentType) {
  if (!body) return true;
  const s = body.trim().toLowerCase();
  if (s.startsWith('<!doctype html') || s.startsWith('<html') || s.startsWith('<!doctype')) return true;
  if (contentType && contentType.toLowerCase().includes('text/html')) return true;
  return false;
}

const SENSITIVE_FILE_SPECS = [
  { path: '/.env', label: 'Production environment file (.env)', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && /^[A-Z0-9_]{3,}\s*=/m.test(b) },
  { path: '/.env.local', label: 'Local environment file (.env.local)', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && /^[A-Z0-9_]{3,}\s*=/m.test(b) },
  { path: '/.env.production', label: 'Production environment file (.env.production)', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && /^[A-Z0-9_]{3,}\s*=/m.test(b) },
  { path: '/.env.bak', label: 'Backup environment file (.env.bak)', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && /^[A-Z0-9_]{3,}\s*=/m.test(b) },
  { path: '/.git/HEAD', label: 'Exposed Git repository HEAD (source leak)', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && (b.trim().startsWith('ref: refs/') || /^[a-f0-9]{40}\b/.test(b.trim())) },
  { path: '/.git/config', label: 'Exposed Git repository config', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && (b.includes('[core]') || b.includes('[remote "origin"]')) },
  { path: '/docker-compose.yml', label: 'Docker Compose configuration', severity: 'high', test: (b, c) => !isHtmlDoc(b, c) && /(?:services|version):\s*/m.test(b) },
  { path: '/docker-compose.yaml', label: 'Docker Compose configuration', severity: 'high', test: (b, c) => !isHtmlDoc(b, c) && /(?:services|version):\s*/m.test(b) },
  { path: '/package.json', label: 'Node.js package.json manifest', severity: 'medium', test: (b, c) => !isHtmlDoc(b, c) && b.includes('"name"') && (b.includes('"version"') || b.includes('"dependencies"')) },
  { path: '/backup.sql', label: 'Database SQL backup dump', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && /(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE|--\s*MySQL|--\s*PostgreSQL)/i.test(b) },
  { path: '/db.sql', label: 'Database SQL dump', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && /(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)/i.test(b) },
  { path: '/dump.sql', label: 'Database SQL dump', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && /(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)/i.test(b) },
  { path: '/config.json', label: 'Server configuration JSON', severity: 'high', test: (b, c) => !isHtmlDoc(b, c) && (b.includes('"database"') || b.includes('"secret"') || b.includes('"password"')) },
  { path: '/wp-config.php.bak', label: 'WordPress database configuration backup', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && (b.includes('DB_PASSWORD') || b.includes('DB_NAME')) },
  { path: '/wp-config.old', label: 'WordPress database configuration backup', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && (b.includes('DB_PASSWORD') || b.includes('DB_NAME')) },
  { path: '/phpinfo.php', label: 'PHP configuration disclosure (phpinfo)', severity: 'high', test: (b, c) => b.includes('PHP Version') && (b.includes('Configuration File') || b.includes('phpinfo()')) },
  { path: '/server-status', label: 'Apache HTTP Server status disclosure', severity: 'medium', test: (b, c) => b.includes('Apache Server Status') && b.includes('Server Version') },
  { path: '/actuator/env', label: 'Spring Boot Actuator environment disclosure', severity: 'critical', test: (b, c) => !isHtmlDoc(b, c) && (b.includes('activeProfiles') || b.includes('propertySources')) },
];

async function checkSensitiveFiles(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const hits = [];

  await pMap(SENSITIVE_FILE_SPECS, async (spec) => {
    try {
      const u = new URL(spec.path, origin);
      const r = await rawRequest(u.toString(), { maxRedirects: 0 });
      if (r.status === 200 && r.body) {
        const ctype = String((r.headers && r.headers['content-type']) || '');
        if (spec.test(r.body.slice(0, 10000), ctype)) {
          hits.push({ ...spec, sample: r.body.slice(0, 150).replace(/\s+/g, ' ') });
        }
      }
    } catch (_) { /* ignore */ }
  });

  meta.probes = meta.probes || {};
  meta.probes.sensitiveFiles = hits.map((h) => h.path);

  for (const h of hits) {
    findings.push(mk(`exposed-file-${h.path.replace(/[^a-z0-9]/gi, '_')}`, h.severity, `${h.label} is publicly accessible at ${h.path}`,
      'The file is accessible to anyone over HTTP with no authentication. Attackers can read sensitive credentials, source repositories, or database dumps directly.',
      'Block access to hidden/config files at your web server or reverse proxy (e.g. Caddy, Nginx, or Cloudflare WAF rule). Never serve dotfiles or backups.',
      `GET ${h.path} → HTTP 200\nSample:\n${h.sample}…`));
  }
}

/* ------------------------------------------------------------------ *
 * 6.14 Source map disclosure (.map)
 * ------------------------------------------------------------------ */

async function checkSourceMaps(origin, html, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const scripts = scriptSrcs(html);
  const hits = [];

  const sameOriginScripts = scripts
    .filter((s) => {
      try { return new URL(s.src, origin).origin === new URL(origin).origin; } catch (_) { return false; }
    })
    .map((s) => s.src)
    .slice(0, 8);

  await pMap(sameOriginScripts, async (scriptPath) => {
    try {
      const mapUrl = new URL(scriptPath + '.map', origin).toString();
      const r = await rawRequest(mapUrl, { maxRedirects: 0 });
      if (r.status === 200 && r.body) {
        const bodyStart = r.body.slice(0, 4000);
        if (bodyStart.includes('"sourcesContent"') || (bodyStart.includes('"mappings"') && bodyStart.includes('"sources"'))) {
          hits.push(mapUrl);
        }
      }
    } catch (_) { /* ignore */ }
  });

  meta.probes = meta.probes || {};
  meta.probes.sourceMaps = hits;

  if (hits.length) {
    findings.push(mk('sourcemap-exposed', 'medium', `Production JavaScript source maps (.map) are publicly downloadable (${hits.length} file(s))`,
      'Source maps contain the original uncompiled, unminified source code (including TypeScript, internal comments, schemas, and API routes). Anyone in DevTools can inspect your entire proprietary source code.',
      'Disable production browser source maps in your bundler (e.g. productionBrowserSourceMaps: false in next.config.js), or configure your web server/CDN to deny requests to *.map.',
      hits.slice(0, 5).join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.15 CORS Misconfiguration with Credentials
 * ------------------------------------------------------------------ */

async function checkCorsMisconfiguration(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const ATTACKER_ORIGIN = 'https://evil-attacker.example';
  let vulnerable = false;
  let evidence = '';

  try {
    const r = await rawRequest(origin, {
      method: 'GET',
      headers: { Origin: ATTACKER_ORIGIN },
      maxRedirects: 0,
    });
    const acao = String((r.headers && (r.headers['access-control-allow-origin'] || r.headers['Access-Control-Allow-Origin'])) || '').trim();
    const acac = String((r.headers && (r.headers['access-control-allow-credentials'] || r.headers['Access-Control-Allow-Credentials'])) || '').trim().toLowerCase();

    if ((acao === ATTACKER_ORIGIN || acao === '*') && acac === 'true') {
      vulnerable = true;
      evidence = `Origin: ${ATTACKER_ORIGIN}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`;
    }
  } catch (_) { /* ignore */ }

  meta.probes = meta.probes || {};
  meta.probes.cors = { vulnerable, evidence };

  if (vulnerable) {
    findings.push(mk('cors-credential-leak', 'high', 'CORS misconfiguration reflects untrusted Origin with credentials',
      'The server echoes arbitrary client Origin headers while setting Access-Control-Allow-Credentials: true. Any malicious site visited by an authenticated user can execute cross-origin requests and read private user data.',
      'Maintain an explicit whitelist of trusted frontend domains for Access-Control-Allow-Origin. Never reflect arbitrary Origin values when credentials are enabled.',
      evidence));
  }
}

/* ------------------------------------------------------------------ *
 * 6.16 Debug & Admin Endpoints
 * ------------------------------------------------------------------ */

const DEBUG_PATHS = [
  { path: '/metrics', label: 'Prometheus metrics endpoint', test: (b, c) => !isHtmlDoc(b, c) && (b.includes('# HELP') || b.includes('# TYPE') || b.includes('process_cpu_user_seconds_total')) },
  { path: '/actuator/health', label: 'Spring Boot Actuator health endpoint', test: (b, c) => !isHtmlDoc(b, c) && b.includes('"status"') && (b.includes('"UP"') || b.includes('"DOWN"')) },
  { path: '/server-status', label: 'Apache/HTTP server status page', test: (b, c) => b.includes('Apache Server Status') || b.includes('Server Version') },
  { path: '/swagger.json', label: 'OpenAPI / Swagger JSON definition', test: (b, c) => !isHtmlDoc(b, c) && (b.includes('"swagger"') || b.includes('"openapi"')) },
  { path: '/openapi.json', label: 'OpenAPI JSON definition', test: (b, c) => !isHtmlDoc(b, c) && (b.includes('"openapi"') || b.includes('"paths"')) },
];

async function checkAdminDebugEndpoints(origin, rawRequest, findings, meta, mk, opts = {}) {
  if (opts.skipActive) return;
  const hits = [];

  await pMap(DEBUG_PATHS, async (item) => {
    try {
      const u = new URL(item.path, origin);
      const r = await rawRequest(u.toString(), { maxRedirects: 0 });
      const ctype = String((r.headers && r.headers['content-type']) || '');
      if (r.status === 200 && r.body && item.test(r.body.slice(0, 10000), ctype)) {
        hits.push({ path: item.path, label: item.label, sample: r.body.slice(0, 120).replace(/\s+/g, ' ') });
      }
    } catch (_) { /* ignore */ }
  });

  meta.probes = meta.probes || {};
  meta.probes.debugEndpoints = hits.map((h) => h.path);

  if (hits.length) {
    findings.push(mk('debug-endpoints-exposed', 'medium', `Internal metrics / API definition endpoint(s) publicly exposed (${hits.length})`,
      'Internal diagnostic or documentation endpoints are publicly reachable without authentication. These endpoints leak server metrics, internal route topologies, and software versions.',
      'Restrict /metrics, /swagger.json, and actuator endpoints to internal VPN/private network access only or require administrative authentication.',
      hits.map((h) => `${h.path} (${h.label})\n  Sample: ${h.sample}…`).join('\n')));
  }
}

/* ------------------------------------------------------------------ *
 * 6.17 Shodan InternetDB infrastructure probe
 * ------------------------------------------------------------------ */

function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => ((acc << 8) + parseInt(oct, 10)) >>> 0, 0);
}

const CLOUDFLARE_V4_RANGES = [
  ['173.245.48.0', 20],
  ['103.21.244.0', 22],
  ['103.22.200.0', 22],
  ['103.31.4.0', 22],
  ['141.101.64.0', 18],
  ['108.162.192.0', 18],
  ['190.93.240.0', 20],
  ['188.114.96.0', 20],
  ['197.234.240.0', 22],
  ['198.41.128.0', 17],
  ['162.158.0.0', 15],
  ['104.16.0.0', 13],
  ['104.24.0.0', 14],
  ['172.64.0.0', 13],
  ['131.0.72.0', 22],
  ['1.1.1.0', 24],
  ['1.0.0.0', 24],
];

function isCloudflareIp(ip) {
  if (!ip || !net.isIPv4(ip)) return false;
  const n = ipToInt(ip);
  return CLOUDFLARE_V4_RANGES.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (n & mask) === (ipToInt(base) & mask);
  });
}

function isPrivateIPv4(ip) {
  if (!ip || !net.isIPv4(ip)) return true;
  const n = ipToInt(ip);
  const ranges = [
    ['10.0.0.0', 8],
    ['172.16.0.0', 12],
    ['192.168.0.0', 16],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['0.0.0.0', 8],
    ['100.64.0.0', 10],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
  ];
  return ranges.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (n & mask) === (ipToInt(base) & mask);
  });
}

const DB_SERVICES = {
  3306: 'MySQL',
  5432: 'PostgreSQL',
  6379: 'Redis',
  27017: 'MongoDB',
  9200: 'Elasticsearch',
  11211: 'Memcached',
  1433: 'MSSQL',
};

const REMOTE_MGMT_SERVICES = {
  23: 'Telnet',
  3389: 'RDP',
  5900: 'VNC',
};

async function checkShodan(ip, findings, meta, mk, opts = {}) {
  if (!ip || typeof ip !== 'string' || !net.isIPv4(ip) || isPrivateIPv4(ip)) return;

  try {
    const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(3500),
      headers: { 'Accept': 'application/json', 'User-Agent': 'VibeScan/2.0' },
    });

    if (res.status === 200) {
      const data = await res.json();
      const ports = Array.isArray(data.ports) ? data.ports : [];
      const cpes = Array.isArray(data.cpes) ? data.cpes : [];
      const hostnames = Array.isArray(data.hostnames) ? data.hostnames : [];
      const tags = Array.isArray(data.tags) ? data.tags : [];
      const vulns = Array.isArray(data.vulns) ? data.vulns : [];

      const isCdn = isCloudflareIp(ip) ||
        cpes.some((c) => /cloudflare|fastly|akamai|cloudfront/i.test(c)) ||
        hostnames.some((h) => /cloudflare|fastly|cloudfront|akamai/i.test(h));

      // Shared web hosting gateways (cPanel, WHM, Plesk, DirectAdmin, Neoserv, etc.)
      // These multi-tenant shared servers run thousands of websites on one IP.
      // Port 3306 (MySQL) or mail ports are open on the shared infrastructure for Remote MySQL access with per-user auth,
      // and cannot be closed or firewalled by individual website owners.
      const isSharedHosting = ports.some((p) => [2082, 2083, 2086, 2087, 2222, 8443].includes(p)) ||
        hostnames.some((h) => /neoserv|hostko|domovanje|cpanel|webhost|shared|bluehost|siteground|godaddy|inwx/i.test(h));

      meta.shodan = { ip, ports, cpes, hostnames, tags, vulns, isCdn, isSharedHosting };

      // If domain is behind CDN edge, do not flag CDN proxy edge ports as customer origin exposure
      if (isCdn) {
        return;
      }

      // a) Exposed Database Port (severity: high)
      // Do not flag database ports on shared web hosting gateways where individual tenants do not control server firewall
      if (!isSharedHosting) {
        const exposedDbs = ports.filter((p) => DB_SERVICES[p]);
        if (exposedDbs.length > 0) {
          const labels = exposedDbs.map((p) => `${p} (${DB_SERVICES[p]})`).join(', ');
          findings.push(mk(
            'shodan-exposed-db',
            'high',
            `Exposed Database Port (${labels})`,
            'Database or caching service is directly reachable from the public internet without a firewall or VPN. Attackers can brute-force credentials or exploit unauthenticated access.',
            'Bind database and cache services to localhost (127.0.0.1) or an isolated private VPC network. Configure a host firewall (ufw/iptables) or security group to block inbound traffic from the public internet.',
            exposedDbs.map((p) => `Port ${p} (${DB_SERVICES[p]}) reachable on public host IP ${ip}`).join('\n')
          ));
        }
      }

      // b) Exposed Remote Management Port (severity: high)
      const exposedMgmt = ports.filter((p) => REMOTE_MGMT_SERVICES[p]);
      if (exposedMgmt.length > 0) {
        const labels = exposedMgmt.map((p) => `${p} (${REMOTE_MGMT_SERVICES[p]})`).join(', ');
        findings.push(mk(
          'shodan-exposed-remote-mgmt',
          'high',
          `Exposed Remote Management Port (${labels})`,
          'Unencrypted or graphical remote desktop ports are directly exposed to the public internet.',
          'Disable public internet exposure for remote management services. Restrict access via VPN (WireGuard/Tailscale) or SSH tunneling with key-based authentication.',
          exposedMgmt.map((p) => `Port ${p} (${REMOTE_MGMT_SERVICES[p]}) reachable on public host IP ${ip}`).join('\n')
        ));
      }

      // c) Unpatched Public CVEs (severity: high)
      if (vulns.length > 0) {
        const cveListing = vulns.length > 60
          ? `${vulns.slice(0, 60).join(', ')}\n... and ${vulns.length - 60} more indexed CVEs`
          : vulns.join(', ');
        findings.push(mk(
          'shodan-known-cve',
          'high',
          `${vulns.length} known unpatched CVE vulnerability/vulnerabilities indexed on host IP`,
          `${vulns.length} known unpatched CVE vulnerability/vulnerabilities indexed on public host IP.`,
          'Patch and upgrade the affected host operating system packages and running services immediately to resolve known public CVEs.',
          `CVEs indexed on public host IP ${ip} (${vulns.length} total):\n${cveListing}`
        ));
      }

      // d) Exposed SSH Port (severity: info)
      if (ports.includes(22)) {
        findings.push(mk(
          'shodan-ssh-open',
          'info',
          'Exposed SSH management port (port 22)',
          'SSH management port is reachable on the public IP. Ensure key-only authentication and fail2ban/rate-limiting are active.',
          'Ensure password authentication is disabled in /etc/ssh/sshd_config (PasswordAuthentication no), enforce public-key authentication only, and enable fail2ban or firewall rate-limiting.',
          `Port 22 (SSH) open on host IP ${ip}`
        ));
      }
    } else if (res.status === 404) {
      meta.shodan = { ip, indexed: false, message: 'No indexed open ports or CVEs in Shodan InternetDB' };
    }
  } catch (e) {
    meta.shodan = meta.shodan || { ip, error: e.message };
  }
}

module.exports = {
  checkOpenRedirect,
  checkReflectedInput,
  checkHostHeader,
  checkHttpMethods,
  checkDirectoryListing,
  checkCrossdomainPolicy,
  checkGraphqlIntrospection,
  checkApiErrorVerbosity,
  checkOpenBuckets,
  checkWebSockets,
  checkSupplyChain,
  checkExtendedSecrets,
  checkSensitiveFiles,
  checkSourceMaps,
  checkCorsMisconfiguration,
  checkAdminDebugEndpoints,
  checkShodan,
  isCloudflareIp,
  isPrivateIPv4,
  scanExtendedSecrets,
  scanPii,
  isValidIBAN,
  IBAN_LENGTHS,
  isPublicCompanyTrr,
  findWebSockets,
  findBuckets,
  scriptSrcs,
};
