'use strict';
/**
 * Peripheral fetches, DNS / email / DNSSEC posture checks, sensitive path sweeps,
 * JS bundle secret/endpoint scanning, and broken internal link checks.
 */

const net = require('net');
const { URL } = require('url');
const { rawRequest } = require('./http');
const { makeFinding } = require('./findings');
const { scanSecrets } = require('./patterns');

async function fetchPeripheral(origin, path, bypassProxy = false, reqFn = rawRequest) {
  try {
    // Proxied only. This used to retry straight from the host on 403/429/WAF,
    // which sent /robots.txt and friends to the target from our own VPS address.
    const r = await reqFn(new URL(path, origin).toString(), { maxRedirects: 3, bypassProxy });
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
async function dnssecSigned(names, reqFn = rawRequest) {
  const endpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
  for (const name of names) {
    for (const ep of endpoints) {
      try {
        const res = await reqFn(`${ep}?name=${encodeURIComponent(name)}&type=DS`, {
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

async function checkDnsSecurity(hostname, res, findings, meta, reqFn = rawRequest) {
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
    dnssecSigned(names, reqFn),
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

// Common sensitive paths — one HEAD/GET each, only reported when they answer 200.
const EXPOSED_PATHS = [
  '/.env', '/.git/HEAD', '/.git/config', '/.DS_Store', '/config.json',
  '/wp-config.php.bak', '/backup.zip', '/backup.sql', '/database.sql',
  '/.aws/credentials', '/server-status', '/phpinfo.php', '/.svn/entries',
];

async function checkPathExposure(origin, findings, meta, reqFn = rawRequest) {
  const results = [];
  await Promise.all(EXPOSED_PATHS.map(async (p) => {
    try {
      const r = await reqFn(new URL(p, origin).toString(), { maxRedirects: 0 });
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

async function checkJsBundles(body, origin, findings, meta, reqFn = rawRequest) {
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
      const r = await reqFn(url, { maxRedirects: 2 });
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

async function checkBrokenLinks(body, origin, findings, meta, reqFn = rawRequest) {
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
      let r = await reqFn(new URL(p, origin).toString(), { method: 'HEAD', maxRedirects: 2 });
      // Some servers reject HEAD (405/501) — retry with GET before calling it broken.
      if (r.status === 405 || r.status === 501) {
        r = await reqFn(new URL(p, origin).toString(), { method: 'GET', maxRedirects: 2 });
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

module.exports = {
  fetchPeripheral,
  MULTI_LABEL_SUFFIXES,
  registrableDomain,
  dnssecSigned,
  checkDnsSecurity,
  EXPOSED_PATHS,
  checkPathExposure,
  decodeHtmlAttr,
  collectScripts,
  checkJsBundles,
  checkBrokenLinks,
};
