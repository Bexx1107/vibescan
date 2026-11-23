'use strict';
/**
 * Transport, TLS, security headers, cookies, and CORS checks.
 */

const { URL } = require('url');
const { makeFinding } = require('./findings');
const { isWafChallenge } = require('./patterns');

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
  // or fetched via HTML-only fallback (e.g. Firecrawl) without origin headers harvested from peripherals,
  // skip to avoid penalizing edge-stripped or missing headers.
  if (!meta?.headersHarvested && (res.status === 429 || res.status === 403 || res.headersUnverified || meta?.headersUnverified || meta?.isWafChallenge || isWafChallenge(res, res.body))) {
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
  if (!meta?.headersHarvested && (res.status === 429 || res.status === 403 || res.headersUnverified || meta?.headersUnverified || meta?.isWafChallenge || isWafChallenge(res, res.body))) {
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
  if ((!meta?.headersHarvested && (res.headersUnverified || meta?.headersUnverified)) || meta?.isWafChallenge || isWafChallenge(res, res.body)) return;
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

function checkCors(res, findings, meta) {
  if (!meta?.headersHarvested && (res.headersUnverified || meta?.headersUnverified)) return;
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

module.exports = {
  checkTransport,
  extractMetaCsp,
  checkSecurityHeaders,
  cspDirective,
  checkModernHeaders,
  parseCookies,
  WAF_COOKIE_RE,
  checkCookies,
  checkCors,
};
