'use strict';
/**
 * Phase 7 — SEO & AI discoverability (2026).
 *
 *   - AI crawler policy (GPTBot, ClaudeBot, Google-Extended, CCBot, …)
 *   - llms.txt presence
 *   - structured-data depth + validation (JSON-LD)
 *   - canonical / hreflang correctness
 *   - indexability (noindex on important pages, blocked CSS/JS, soft-404)
 *   - Open Graph / Twitter card completeness
 *   - Core Web Vitals as a ranking input (fed from webvitals.js)
 */

/* ------------------------------------------------------------------ *
 * AI crawler registry
 * ------------------------------------------------------------------ */

const AI_CRAWLERS = [
  ['GPTBot', /GPTBot/i],
  ['ChatGPT-User', /ChatGPT-User/i],
  ['OAI-SearchBot', /OAI-SearchBot/i],
  ['ClaudeBot', /ClaudeBot/i],
  ['Claude-Web', /Claude-Web/i],
  ['anthropic-ai', /anthropic-ai/i],
  ['Google-Extended', /Google-Extended/i],
  ['GoogleOther', /GoogleOther/i],
  ['Applebot-Extended', /Applebot-Extended/i],
  ['CCBot', /CCBot/i],
  ['Bytespider', /Bytespider/i],
  ['PerplexityBot', /PerplexityBot/i],
  ['DeepSeekBot', /DeepSeekBot/i],
  ['MistralAI', /MistralAI|MistralBot/i],
  ['Meta-ExternalAgent', /meta-externalagent/i],
  ['FacebookBot', /FacebookBot/i],
  ['Amazonbot', /Amazonbot/i],
  ['cohere-ai', /cohere-ai/i],
  ['Diffbot', /Diffbot/i],
  ['TencentBot', /TencentBot/i],
  ['YouBot', /YouBot/i],
  ['DuckAssistBot', /DuckAssistBot/i],
];

/* ------------------------------------------------------------------ *
 * Structured-data validation (minimal, JSON-LD only)
 * ------------------------------------------------------------------ */

function extractJsonLd(html) {
  const out = [];
  const re = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) {
    const raw = m[1].trim();
    try {
      const parsed = JSON.parse(raw);
      const list = Array.isArray(parsed) ? parsed : (parsed['@graph'] ? parsed['@graph'] : [parsed]);
      for (const item of list) out.push({ ok: true, data: item });
    } catch (e) {
      out.push({ ok: false, error: e.message.slice(0, 120), raw: raw.slice(0, 200) });
    }
  }
  return out;
}

const REQUIRED_PROPS = {
  Organization: ['name', 'url', 'logo'],
  WebSite: ['name', 'url'],
  BreadcrumbList: ['itemListElement'],
  Product: ['name', 'offers'],
  Offer: ['price', 'priceCurrency'],
  Article: ['headline', 'author', 'datePublished'],
  BlogPosting: ['headline', 'author', 'datePublished'],
  FAQPage: ['mainEntity'],
  LocalBusiness: ['name', 'address'],
  Person: ['name'],
  Event: ['name', 'startDate', 'location'],
};

function hasNestedEntityType(node, targetTypes) {
  if (!node || typeof node !== 'object') return false;
  if (Array.isArray(node)) return node.some((item) => hasNestedEntityType(item, targetTypes));
  const t = node['@type'];
  const ts = Array.isArray(t) ? t : (t ? [t] : []);
  if (ts.some((x) => targetTypes.includes(x))) return true;
  for (const val of Object.values(node)) {
    if (val && typeof val === 'object' && hasNestedEntityType(val, targetTypes)) return true;
  }
  return false;
}

function isIntentionallyPrivate(html, res, peripherals) {
  const metas = (html || '').match(/<meta\b[^>]*>/gi) || [];
  let hasNoindexMeta = false;
  for (const tag of metas) {
    if (/\bname\s*=\s*["']?robots["']?/i.test(tag) && /\bcontent\s*=\s*["'][^"']*noindex/i.test(tag)) {
      hasNoindexMeta = true;
      break;
    }
  }
  const xRobots = res && res.headers && res.headers['x-robots-tag'];
  if (xRobots && /noindex/i.test(String(xRobots))) hasNoindexMeta = true;
  const robotsTxt = peripherals && peripherals.robots && peripherals.robots.status === 200 ? (peripherals.robots.body || '') : '';
  const blocksAllRobots = /disallow:\s*\/\s*$/im.test(robotsTxt);
  return hasNoindexMeta && blocksAllRobots;
}

function checkJsonLd(html, origin, findings, meta, mk, peripherals, res) {
  if (meta && meta.isWafChallenge) return;
  const blocks = extractJsonLd(html);
  const types = [];
  const errors = [];
  const missingProps = [];
  const privatePage = isIntentionallyPrivate(html, res, peripherals);

  for (const b of blocks) {
    if (!b.ok) {
      errors.push(b.error + ' — ' + b.raw.replace(/\s+/g, ' '));
      continue;
    }
    const t = b.data && b.data['@type'];
    const ts = Array.isArray(t) ? t : [t];
    for (const one of ts) {
      if (!one) continue;
      types.push(one);
      const req = REQUIRED_PROPS[one];
      if (req) {
        const missing = req.filter((p) => !(p in b.data));
        if (missing.length) missingProps.push(`${one}: missing ${missing.join(', ')}`);
      }
    }
  }

  meta.seo = meta.seo || {};
  meta.seo.structuredData = { types, blocks: blocks.length, errors: errors.length };
  meta.seo.isPrivatePortal = privatePage;

  if (privatePage) {
    return { blocks, types, errors };
  }

  if (!blocks.length) {
    findings.push(mk('seo-structured-data', 'medium', 'No structured data (JSON-LD)',
      'Rich results (breadcrumbs, product price, FAQ, event dates) are driven by schema.org markup. Without it, search engines infer nothing and AI answer engines have less to cite.',
      'Add JSON-LD: at minimum Organization + WebSite, plus the page type (Product, Article, LocalBusiness…).'));
  } else {
    if (errors.length) {
      findings.push(mk('seo-structured-data-invalid', 'medium', `${errors.length} unparseable JSON-LD block(s)`,
        'Malformed structured data is silently ignored by crawlers, so you lose every rich result on the page.',
        'Validate the JSON-LD (Rich Results Test) and fix syntax errors.',
        errors.slice(0, 5).join('\n')));
    }
    if (missingProps.length) {
      findings.push(mk('seo-structured-data-incomplete', 'low', `${missingProps.length} structured-data type(s) missing required properties`,
        'Required schema.org properties drive eligibility for rich results; missing fields disqualify the entity.',
        'Add the missing properties listed in the evidence.',
        missingProps.slice(0, 8).join('\n')));
    }
    const hasWebSiteWithSearch = blocks.some((b) => b.ok && b.data && (b.data['@type'] === 'WebSite') && b.data.potentialAction);
    const hasOrg = types.includes('Organization') || blocks.some((b) => b.ok && hasNestedEntityType(b.data, ['Organization', 'WebSite', 'LocalBusiness', 'ProfessionalService', 'Corporation']));
    if (!hasOrg && !hasWebSiteWithSearch) {
      findings.push(mk('seo-structured-data-base', 'low', 'No Organization/WebSite entity in structured data',
        'A site-wide Organization + WebSite node gives search and AI engines a canonical brand entity to attach everything else to.',
        'Add a site-wide JSON-LD block with Organization (name, url, logo, sameAs) and WebSite.'));
    }
  }

  // llms.txt — emerging AI-discoverability convention.
  const llms = peripherals && peripherals.llms;
  const llmsFull = peripherals && peripherals.llmsFull;
  meta.seo.llmsTxt = !!(llms && llms.status === 200);
  meta.seo.llmsFullTxt = !!(llmsFull && llmsFull.status === 200);
  if (!llms || llms.status !== 200) {
    findings.push(mk('seo-llms-txt', 'info', 'No /llms.txt',
      'llms.txt (2024–2026 convention) gives LLM crawlers a curated, markdown index of what you want them to read — the AI-era equivalent of sitemap.xml.',
      'Publish /llms.txt with an H1 title, a one-line summary and linked sections.'));
  } else if (llms.body) {
    const body = String(llms.body);
    const hasH1 = /^#\s+[^\r\n]+/m.test(body);
    const hasMdLinks = /\[.+?\]\((?:https?:\/\/|\/)[^\s\)]+\)/.test(body);
    if (!hasH1) {
      findings.push(mk('seo-llms-txt-h1', 'info', 'llms.txt missing H1 title',
        'The llms.txt specification and Google PageSpeed Insights expect an H1 heading at the top specifying the project or organization name.',
        'Add an H1 heading at the top of /llms.txt: # Your Project Name'));
    }
    if (!hasMdLinks) {
      findings.push(mk('seo-llms-txt-links', 'info', 'llms.txt links are not in Markdown format',
        'Google PageSpeed Insights (Agentic Browsing) and AI crawlers require llms.txt links to use standard Markdown format: [Title](url): Description. Plain text URLs without brackets are not recognized as links by Markdown AST parsers.',
        'Format links in /llms.txt using Markdown brackets: - [Page Title](https://example.com/page): Description'));
    }
  }

  return { blocks, types, errors };
}

/* ------------------------------------------------------------------ *
 * robots.txt AI-crawler policy
 * ------------------------------------------------------------------ */

function parseRobotsGroups(txt) {
  const groups = [];
  let current = null;
  for (const rawLine of String(txt || '').split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const field = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (field === 'user-agent') {
      // A group is a run of one or more User-agent lines followed by rules.
      // Only start a new group once the current one has directives; consecutive
      // User-agent lines share the same rules and belong to the same group.
      if (!current || current.dirs) { current = { ua: [], allow: [], disallow: [], dirs: false }; groups.push(current); }
      current.ua.push(value);
    } else if (field === 'disallow' && current) {
      current.disallow.push(value);
      current.dirs = true;
    } else if (field === 'allow' && current) {
      current.allow.push(value);
      current.dirs = true;
    }
  }
  return groups;
}

function checkAiCrawlerPolicy(html, origin, findings, meta, mk, peripherals) {
  const robots = peripherals && peripherals.robots;
  const txt = robots && robots.status === 200 ? (robots.body || '') : '';
  const groups = parseRobotsGroups(txt);

  const seen = new Map(); // crawler -> named group
  let wildcard = null;     // the `User-agent: *` group, if any
  for (const g of groups) {
    for (const ua of g.ua) {
      if (ua === '*') { if (!wildcard) wildcard = g; }
      for (const [name, re] of AI_CRAWLERS) {
        // A named group that matches this exact bot wins over `*`.
        if (re.test(ua) && ua !== '*') seen.set(name, g);
      }
    }
  }

  const blocked = [];
  const allowed = [];
  for (const [name] of AI_CRAWLERS) {
    // Per the robots.txt spec a crawler obeys the most specific matching group;
    // if none matches its token by name it falls back to the `*` group. The old
    // code ignored `*` entirely, so a blanket `User-agent: * / Disallow: /`
    // (which DOES block every AI bot) was reported as "unlisted → allowed".
    const g = seen.get(name) || wildcard;
    if (!g) { allowed.push(name + ' (unlisted)'); continue; }
    const blocksAll = g.disallow.some((d) => d === '/');
    if (blocksAll && !g.allow.some((a) => a === '/')) blocked.push(name);
    else allowed.push(name);
  }

  const explicitAiAgents = [...seen.keys()];
  const hasLlmsTxt = Boolean(peripherals && peripherals.llms && peripherals.llms.status === 200);
  meta.seo = meta.seo || {};
  meta.seo.aiCrawlers = {
    blocked,
    allowed,
    explicitAgents: explicitAiAgents,
    explicitPolicy: explicitAiAgents.length > 0 || blocked.length > 0 || hasLlmsTxt,
    hasRobots: !!(robots && robots.status === 200),
  };

  if (!robots || robots.status !== 200) {
    // Missing robots.txt is flagged exclusively by `seo-robots` in lib/scanner.js.
    // Do NOT emit a second "No robots.txt" finding here.
    return;
  }

  if (blocked.length === 0 && explicitAiAgents.length === 0 && !hasLlmsTxt) {
    findings.push(mk('seo-ai-content-scraped', 'info', `Content is open to ${AI_CRAWLERS.length} AI crawlers`,
      'Your content can be ingested and reused by AI vendors with no explicit AI crawler rules in robots.txt. That may be what you want — but it should be a decision, not a default.',
      'If you want control, add explicit Allow/Disallow rules per AI user-agent in robots.txt or publish /llms.txt.',
      allowed.join(', ')));
  } else if (blocked.length > 0) {
    findings.push(mk('seo-ai-crawler-policy', 'info', `${blocked.length} AI crawler(s) explicitly blocked`,
      'You have taken an explicit opt-out stance, which is good practice to document.',
      'No action needed — keep the list current as new AI vendors appear.',
      'Blocked: ' + blocked.join(', ')));
  } else if (explicitAiAgents.length > 0 || hasLlmsTxt) {
    findings.push(mk('seo-ai-crawler-policy', 'info', 'AI crawlers permitted with explicit guidance',
      'AI crawlers are allowed under explicit robots.txt rules or /llms.txt guidance.',
      'No action needed — keep the list current as new AI vendors appear.',
      hasLlmsTxt ? 'llms.txt present' : 'Permitted: ' + explicitAiAgents.join(', ')));
  }
}

/* ------------------------------------------------------------------ *
 * Canonical / hreflang / indexability / social
 * ------------------------------------------------------------------ */

function checkIndexability(html, origin, res, findings, meta, mk, peripherals) {
  if (meta && meta.isWafChallenge) return;
  const metas = html.match(/<meta\b[^>]*>/gi) || [];
  const attrVal = (tag, name) => {
    const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i'));
    return m ? (m[1] ?? m[2] ?? m[3] ?? '') : null;
  };

  let robotsMeta = null;
  for (const tag of metas) {
    const n = attrVal(tag, 'name');
    if (n && n.toLowerCase() === 'robots') { robotsMeta = attrVal(tag, 'content') || ''; break; }
  }
  const xRobots = res && res.headers && res.headers['x-robots-tag'];
  meta.seo = meta.seo || {};
  meta.seo.robotsMeta = robotsMeta;
  const privatePage = isIntentionallyPrivate(html, res, peripherals);
  if (privatePage) {
    findings.push(mk('seo-private-noindex', 'info', 'Private / auth-gated page intentionally opts out of indexing',
      'Both `robots.txt` (`Disallow: /`) and `<meta name="robots" content="noindex">` are set, indicating a deliberate private or login-gated application.',
      'No action needed if this application is intended to remain private and unindexed.',
      `robots.txt: Disallow: /\nmeta robots: ${robotsMeta || xRobots}`));
    return;
  }

  if (robotsMeta && /noindex/i.test(robotsMeta)) {
    findings.push(mk('seo-noindex', 'high', 'Homepage is marked noindex',
      'A noindex directive removes the page from search results entirely — usually a staging setting that shipped to production.',
      'Remove noindex (or scope it to genuinely private pages).', robotsMeta));
  }
  if (xRobots && /noindex/i.test(String(xRobots))) {
    findings.push(mk('seo-noindex-header', 'high', 'X-Robots-Tag: noindex on a public page',
      'The header overrides the visible page and silently de-indexes it.',
      'Remove noindex from the X-Robots-Tag header on public routes.', String(xRobots)));
  }

  // Canonical correctness.
  const canonicalTag = (html.match(/<link\b[^>]*rel\s*=\s*["']canonical["'][^>]*>/i) || [''])[0];
  const canonical = attrVal(canonicalTag, 'href');
  if (canonical) {
    try {
      const cu = new URL(canonical, origin);
      const originUrl = new URL(origin);
      const cuApex = cu.hostname.replace(/^www\./i, '').toLowerCase();
      const originApex = originUrl.hostname.replace(/^www\./i, '').toLowerCase();

      if (cuApex !== originApex) {
        // Genuinely different domains / entity (e.g. example.com -> otherdomain.com)
        findings.push(mk('seo-canonical-cross-domain', 'medium', 'Canonical points at a different domain',
          `The page declares \`${canonical}\` as its canonical URL, telling search engines to rank another domain instead of this one.`,
          'Point rel=canonical at the preferred URL on this site (or remove it).',
          `page: ${origin}\ncanonical: ${canonical}`));
      } else if (cu.hostname.toLowerCase() !== originUrl.hostname.toLowerCase()) {
        // Same domain, but www vs apex mismatch (e.g. www.example.com vs example.com)
        findings.push(mk('seo-canonical-www-mismatch', 'info', 'Canonical points between apex and www',
          `The page on \`${originUrl.hostname}\` declares \`${canonical}\` as its canonical URL. Search engines treat this as an apex preference rather than a cross-domain issue. Ensure your 301/308 redirects match this canonical preference.`,
          `Align rel=canonical with your primary served URL (${originUrl.hostname}) to avoid redirect/indexing ambiguity.`,
          `page: ${originUrl.hostname}\ncanonical: ${cu.hostname}`));
      }
    } catch (e) { /* malformed canonical — covered by absence checks elsewhere */ }
  }

  // hreflang correctness.
  const altTags = html.match(/<link\b[^>]*hreflang\s*=[^>]*>/gi) || [];
  const hrefLangs = [];
  const hrefLangUrls = new Set();
  const badHreflang = [];
  for (const t of altTags) {
    const lang = attrVal(t, 'hreflang');
    const href = attrVal(t, 'href');
    if (!lang) continue;
    hrefLangs.push(lang);
    if (href) hrefLangUrls.add(href.replace(/\/+$/, ''));
    if (lang !== 'x-default' && !/^[a-z]{2}(-[A-Za-z]{2,4})?$/.test(lang)) badHreflang.push(lang);
    if (href && !/^https?:\/\//i.test(href)) badHreflang.push(`${lang} → relative href`);
  }
  meta.seo.hreflang = hrefLangs;
  const baseLangs = new Set(
    hrefLangs
      .filter((l) => l !== 'x-default')
      .map((l) => l.split('-')[0].toLowerCase())
  );
  if (badHreflang.length) {
    findings.push(mk('seo-hreflang-invalid', 'low', `${badHreflang.length} invalid hreflang value(s)`,
      'Malformed hreflang codes are ignored, so those language versions are treated as duplicates.',
      'Use ISO 639-1 language codes with optional ISO 3166-1 region (e.g. en, en-GB, sl-SI) and absolute URLs.',
      badHreflang.join(', ')));
  } else if (baseLangs.size > 1 && hrefLangUrls.size > 1 && !hrefLangs.includes('x-default')) {
    findings.push(mk('seo-hreflang-xdefault', 'info', 'hreflang is missing x-default',
      'x-default tells search engines which version to serve when no language matches the user on a multi-language site.',
      'Add <link rel="alternate" hreflang="x-default" href="…">.'));
  }

  // Social cards.
  const og = ['og:title', 'og:description', 'og:image', 'og:url', 'og:type']
    .filter((p) => !new RegExp(`property\\s*=\\s*["']${p}["']`, 'i').test(html));
  const tw = ['twitter:card', 'twitter:title', 'twitter:description', 'twitter:image']
    .filter((p) => !new RegExp(`name\\s*=\\s*["']${p}["']`, 'i').test(html));
  meta.seo.og = { missing: og, missingTwitter: tw };

  if (og.includes('og:image') || tw.includes('twitter:image')) {
    findings.push(mk('seo-social-image', 'low', 'No social share image',
      'Links shared on Slack, LinkedIn, X or WhatsApp render as bare text, which measurably cuts click-through.',
      'Add og:image (1200×630) plus twitter:card=summary_large_image.'));
  }
  if (tw.length >= 3) {
    findings.push(mk('seo-twitter-card', 'info', `${tw.length} Twitter/X card tag(s) missing`,
      'X falls back to Open Graph when card tags are absent, but explicit tags give you full control of the preview.',
      'Add the missing twitter:* tags (you can mirror the og:* values).'));
  }
}

/* ------------------------------------------------------------------ *
 * Core Web Vitals as a ranking input
 * ------------------------------------------------------------------ */

const CWV_THRESHOLDS = {
  lcp: { good: 2500, poor: 4000, unit: 'ms', label: 'LCP' },
  cls: { good: 0.1, poor: 0.25, unit: '', label: 'CLS' },
  tbt: { good: 200, poor: 600, unit: 'ms', label: 'TBT (INP proxy)' },
  ttfb: { good: 800, poor: 1800, unit: 'ms', label: 'TTFB' },
};

function checkCwv(metrics, findings, meta, mk) {
  if (!metrics) return null;
  const verdicts = {};
  const failing = [];

  const measured = metrics.measured || null;
  for (const key of ['lcp', 'cls', 'tbt', 'ttfb']) {
    const t = CWV_THRESHOLDS[key];
    const v = metrics[key];
    // CLS and TBT are the two metrics where exactly 0 is a *valid, best-case*
    // result (no layout shift, no long tasks). The old code treated any 0 as
    // "n/a", so a flawless page was reported as "not measured" instead of
    // "good". LCP and TTFB of 0, by contrast, always mean the measurement
    // never happened, so those stay "n/a".
    const zeroIsGood = key === 'cls' || key === 'tbt';
    const isZero = v === 0;
    // Require positive proof the observer registered — an all-zero metrics
    // object from a failed/never-injected measurement must stay "n/a" rather
    // than masquerade as a perfect score.
    const knownZero = isZero && zeroIsGood && !!measured && measured[key] === true;
    if (v === undefined || v === null || (isZero && !knownZero)) { verdicts[key] = 'n/a'; continue; }
    const rounded = key === 'cls' ? Math.round(v * 1000) / 1000 : Math.round(v);
    if (v <= t.good) verdicts[key] = 'good';
    else if (v <= t.poor) { verdicts[key] = 'needs-improvement'; failing.push({ key, t, v: rounded }); }
    else { verdicts[key] = 'poor'; failing.push({ key, t, v: rounded }); }
  }

  meta.performance = meta.performance || {};
  meta.performance.metrics = {
    lcp: Math.round(metrics.lcp || 0),
    cls: Math.round((metrics.cls || 0) * 1000) / 1000,
    tbt: Math.round(metrics.tbt || 0),
    ttfb: Math.round(metrics.ttfb || 0),
    fcp: Math.round(metrics.fcp || 0),
    transferBytes: metrics.transferBytes || 0,
    requests: metrics.requests || 0,
  };
  meta.performance.verdicts = verdicts;
  meta.performance.hosts = metrics.hosts || {};

  for (const f of failing) {
    const sev = verdicts[f.key] === 'poor' ? 'high' : 'medium';
    findings.push(mk(`perf-${f.key}`, sev,
      `${f.t.label} = ${f.v}${f.t.unit} (${verdicts[f.key]})`,
      `Core Web Vitals are a confirmed ranking input, and INP replaced FID as the responsiveness metric. Google's "good" threshold is ≤ ${f.t.good}${f.t.unit}, "poor" is > ${f.t.poor}${f.t.unit}.`,
      `Reduce ${f.t.label} — see the evidence and the performance notes for the largest contributors.`));
  }

  if (metrics.tbt > 200 && metrics.longTasks) {
    findings.push(mk('perf-longtasks', 'medium', `${metrics.longTasks} long main-thread task(s)`,
      'Every task over 50 ms blocks input handling. Users feel this as lag on buttons, menus and forms — and it is what INP measures.',
      'Split long tasks with `await yieldToMain()` / scheduler.yield(), defer non-critical JS, and trim third-party scripts.'));
  }
  if (metrics.transferBytes > 3 * 1024 * 1024) {
    findings.push(mk('perf-transfer', 'medium', `${(metrics.transferBytes / (1024 * 1024)).toFixed(1)} MB transferred across ${metrics.requests} request(s)`,
      'Payload weight directly extends LCP on mobile connections and inflates data cost for EU users.',
      'Compress and resize images (AVIF/WebP), code-split JS, tree-shake bundles, and lazy-load below-the-fold media.'));
  }
  if (metrics.errorCodes && metrics.errorCodes.length) {
    findings.push(mk('perf-failed-requests', 'low', `${metrics.errorCodes.length} sub-resource(s) returned 4xx/5xx`,
      'Broken sub-resources stall rendering and waste crawl budget.',
      'Fix or remove the failing requests.',
      metrics.errorCodes.join(', ')));
  }
  if (metrics.failedRequests) {
    findings.push(mk('perf-network-errors', 'low', `${metrics.failedRequests} network request(s) failed outright`,
      'Failed requests (DNS, TLS, CORS, aborts) leave holes in the UI and can block first paint.',
      'Open DevTools → Network and fix each failing request.',
      Array.isArray(metrics.failedUrls) && metrics.failedUrls.length ? metrics.failedUrls.join('\n') : null));
  }
  return verdicts;
}

module.exports = {
  checkJsonLd,
  checkAiCrawlerPolicy,
  checkIndexability,
  checkCwv,
  extractJsonLd,
  parseRobotsGroups,
  isIntentionallyPrivate,
  AI_CRAWLERS,
  CWV_THRESHOLDS,
};
