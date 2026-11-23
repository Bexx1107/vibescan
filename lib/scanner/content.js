'use strict';
/**
 * HTML body, GDPR/EU compliance policy, SEO, and frontend quality analyzers.
 */

const { URL } = require('url');
const seoLib = require('../seo');
const { makeFinding, slug, POLICY_RULES } = require('./findings');
const { scanSecrets } = require('./patterns');

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
      fix: 'Publish /robots.txt with a Sitemap: directive and deliberate crawl rules.',
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

  // Compression & caching headers are unavailable when HTML was retrieved via WAF bypass without origin headers.
  const headersUnavailable = Boolean((res.headersUnverified || (meta && meta.headersUnverified)) && !(meta && meta.headersHarvested));

  // Compression
  const enc = res.headers['content-encoding'];
  if (!enc && !headersUnavailable) {
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
  if (!headersUnavailable && !res.headers['cache-control'] && !res.headers['etag'] && !res.headers['last-modified']) {
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

module.exports = {
  checkBody,
  checkPolicies,
  checkCompliance,
  checkSeo,
  checkQuality,
};
