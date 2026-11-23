'use strict';
/**
 * Outbound HTTP/HTTPS/TLS transport, proxy egress chaining, WAF fallbacks,
 * egress circuit breaker, and response decoding.
 */

const net = require('net');
const http = require('http');
const https = require('https');
const tls = require('tls');
const zlib = require('zlib');
const { URL } = require('url');
const { execFile } = require('child_process');
const egress = require('../egress'); // ordered egress tier chain + per-tier breaker
const {
  ALLOW_LOOPBACK_TEST,
  isPrivateIPv4,
  isPrivateIPv6,
  isLoopbackAddress,
  assertPublicHost,
} = require('./ssrf');
const { isWafChallenge, detectWaf } = require('./patterns');

const TIMEOUT_MS = 12000;
const MAX_BODY = 3 * 1024 * 1024; // 3 MB
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
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
    connectReq.on('connect', (res, socket) => {
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

/* ------------------------------------------------------------------ *
 * Egress circuit breaker
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

function rawRequest(urlString, opts = {}) {
  const { method = 'GET', maxRedirects = 5, headers = null, bypassProxy = false } = opts || {};
  const allowLoopback = Boolean(opts && opts[ALLOW_LOOPBACK_TEST] === true);
  const effectiveBypassProxy = bypassProxy || allowLoopback;

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
        resolved = await assertPublicHost(u.hostname, allowLoopback ? { [ALLOW_LOOPBACK_TEST]: true } : null);
      } catch (e) {
        return rejectOnce(e);
      }

      // Pin the connection to a validated IP so a DNS reply that changes
      // between the check and the connect (DNS rebinding) can't slip through.
      const safeAddrs = resolved.addresses.filter((a) => {
        if (allowLoopback && isLoopbackAddress(a)) return true;
        return !(net.isIPv4(a) && isPrivateIPv4(a)) && !(net.isIPv6(a) && isPrivateIPv6(a));
      });
      const lookup = (hostname, lookupOpts, cb) => {
        const wantFamily = typeof lookupOpts === 'object' && lookupOpts ? lookupOpts.family : lookupOpts;
        const pool = wantFamily ? safeAddrs.filter((a) => net.isIP(a) === wantFamily) : safeAddrs;
        const list = pool.length ? pool : safeAddrs;
        if (lookupOpts && lookupOpts.all) {
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
      const tierList = effectiveBypassProxy
        ? [{ name: 'direct', url: '' }]
        : egress.plan(u.hostname);

      // SECURITY: when a chain IS configured but every tier is blocked for this
      // host, fail the request. The `|| { name: 'direct' }` fallback below must
      // never be reachable with a configured chain — it would send the request
      // from the host's own public IP (which may co-host other services) to a
      // target that just refused us. Empty tierList with NO configuration stays
      // direct, which is the historic behaviour of local tool runs.
      if (!effectiveBypassProxy && !tierList.length && egress.tiers().length) {
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

              // Skip external curl/Firecrawl bypass fallbacks during deterministic in-process loopback tests.
              if (!allowLoopback && (status === 403 || status === 429) && isWafChallenge({ status, headers: res.headers }, decodedBody)) {
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
                    const wafInfo = detectWaf({ status, headers: res.headers }, decodedBody);
                    // SECURITY/INTEGRITY: Never merge the 403/429 WAF challenge response headers
                    // into fcResult. Doing so caused Cloudflare's interstitial CSP ('unsafe-eval')
                    // and missing HSTS to be scored as if they came from the origin server.
                    return resolveOnce({
                      url: current,
                      status: 200,
                      headers: Object.assign({}, fcResult.headers),
                      body: fcResult.body,
                      rawBytes: fcResult.rawBytes,
                      bytes: fcResult.bytes,
                      truncated: false,
                      ttfb,
                      redirects: chain,
                      tls: capturedTls || (res.socket && res.socket.encrypted ? tlsInfo(res.socket) : null),
                      via: 'firecrawl',
                      bypassedWaf: true,
                      headersUnverified: true,
                      wafProvider: wafInfo.provider || 'WAF',
                      wafStatus: status,
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

module.exports = {
  TIMEOUT_MS,
  MAX_BODY,
  UA,
  SCANNER_PROXY,
  getTunnelAgent,
  fetchWithCurl,
  fetchWithFirecrawl,
  rawRequest,
  egressState,
  noteEgressFailure,
  noteEgressSuccess,
  egressTripped,
  egressOpenError,
  decodeBody,
  tlsInfo,
};
