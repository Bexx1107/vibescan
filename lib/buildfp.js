'use strict';
/**
 * Build fingerprint collector.
 *
 * Runs inside the existing scan, on the HTML that is already in memory plus a
 * handful of optional same-origin GETs for well-known public files. It returns
 * a COMPACT, bounded summary (no raw HTML, no response bodies) that is stored
 * as `report.meta.build` and consumed by lib/verify.js.
 *
 * Why compact: PLAN-LEADERBOARD.md §2.1 forbids storing page bodies and
 * evidence payloads. The leaderboard needs decisions, not documents.
 */

const MAX_PATH_SAMPLE = 40;
const MAX_TEXT = 1200;

/* ------------------------------------------------------------------ *
 * Platform detection — mirrors lib/verify.js but runs at scan time so the
 * result is recorded once and can be audited later.
 * ------------------------------------------------------------------ */

const PLATFORMS = [
  ['wordpress', /wp-content|wp-includes|wp-json|<meta[^>]+name\s*=\s*["']generator["'][^>]+wordpress/i],
  ['shopify', /cdn\.shopify\.com|shopify\.theme/i],
  ['wix', /wixstatic|static\.parastorage\.com/i],
  ['squarespace', /squarespace-cdn\.com|static\.squarespace\.com/i],
  ['webflow', /data-wf-|webflow\.js/i],
  ['nextjs', /__NEXT_DATA__|_next\/static/i],
  ['nuxt', /__NUXT__|_nuxt\//i],
  ['astro', /astro-island|astro\/client/i],
];

function detectPlatform(body) {
  for (const [name, re] of PLATFORMS) if (re.test(body)) return name;
  return null;
}

/* ------------------------------------------------------------------ *
 * Meta tag extraction (targeted, not a DOM parse)
 * ------------------------------------------------------------------ */

function metaContent(html, name) {
  const re = new RegExp(
    `<meta[^>]+(?:name|property)\\s*=\\s*["']${name}["'][^>]*content\\s*=\\s*["']([^"']*)["']`,
    'i'
  );
  const alt = new RegExp(
    `<meta[^>]+content\\s*=\\s*["']([^"']*)["'][^>]*(?:name|property)\\s*=\\s*["']${name}["']`,
    'i'
  );
  const m = html.match(re) || html.match(alt);
  return m ? m[1].trim() : null;
}

function generators(html) {
  const out = [];
  const re = /<meta[^>]+name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html))) out.push(m[1].trim());
  return out.slice(0, 5);
}

function stripTags(chunk) {
  return chunk
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Text of the page footer, tag-stripped and bounded. Credits live here, and
 * `<footer>` is only one of the ways to mark it — plenty of sites (especially
 * Tailwind/React ones) use a div with a footer-ish class, so fall back to the
 * last part of the document.
 */
function footerText(html) {
  const direct = html.match(/<footer\b[^>]*>([\s\S]{0,6000}?)<\/footer>/i);
  if (direct) {
    const text = stripTags(direct[1]);
    if (text) return text.slice(0, MAX_TEXT);
  }

  // class/id containing "footer" on any element, taking a bounded inner chunk.
  const byClass = html.match(
    /<(?:div|section|aside)\b[^>]*(?:class|id)\s*=\s*["'][^"']*footer[^"']*["'][^>]*>([\s\S]{0,6000}?)<\/(?:div|section|aside)>/i
  );
  if (byClass) {
    const text = stripTags(byClass[1]);
    if (text) return text.slice(0, MAX_TEXT);
  }

  // Last resort: the tail of the document usually holds the legal credit.
  if (html.length > 400) {
    const text = stripTags(html.slice(-4000));
    if (text && /(©|copyright|d\.o\.o|s\.p\.|all rights reserved)/i.test(text)) {
      return text.slice(-MAX_TEXT);
    }
  }
  return null;
}

/**
 * Collect asset paths, keeping their pathname only.
 * Cross-origin CDNs are dropped (they say nothing about how the site was
 * built); same-origin absolute URLs are reduced to their path so the
 * `/wp-content/` and `/_next/` checks still work.
 */
function assetPaths(html, origin) {
  const out = new Set();
  const re = /(?:href|src)\s*=\s*["']([^"']+\.(?:css|js|mjs))["']/gi;
  let m;
  while ((m = re.exec(html)) && out.size < MAX_PATH_SAMPLE) {
    let p = m[1];
    if (/^\/\//.test(p)) p = 'https:' + p;
    if (/^https?:\/\//i.test(p)) {
      try {
        const u = new URL(p);
        if (origin && u.origin !== origin) continue; // third-party CDN
        p = u.pathname + u.search;
      } catch {
        continue;
      }
    }
    out.add(p.slice(0, 200));
  }
  return [...out];
}

/**
 * Extract hostnames from Content-Security-Policy headers and meta tags.
 * Bounded summary for meta.build.cspHosts.
 */
function extractCspHosts(res, html) {
  const hosts = new Set();
  const rawPolicies = [];

  if (res && res.headers) {
    for (const [k, v] of Object.entries(res.headers)) {
      if (/^content-security-policy/i.test(k)) {
        if (Array.isArray(v)) rawPolicies.push(...v);
        else if (typeof v === 'string') rawPolicies.push(v);
      }
    }
  }

  if (html) {
    const metaRe = /<meta[^>]+http-equiv\s*=\s*["']content-security-policy["'][^>]*content\s*=\s*["']([^"']+)["']/gi;
    const metaReAlt = /<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]*http-equiv\s*=\s*["']content-security-policy["']/gi;
    let m;
    while ((m = metaRe.exec(html))) rawPolicies.push(m[1]);
    while ((m = metaReAlt.exec(html))) rawPolicies.push(m[1]);
  }

  for (const policy of rawPolicies) {
    const directives = policy.split(';');
    for (const directive of directives) {
      const parts = directive.trim().split(/\s+/);
      for (let i = 1; i < parts.length; i++) {
        let token = parts[i].trim().replace(/['"]/g, '');
        if (!token) continue;
        if (/^(self|unsafe-inline|unsafe-eval|strict-dynamic|none|report-sample)$/i.test(token)) continue;
        if (/^(data|blob|filesystem|mediastream):/i.test(token)) continue;
        if (/^\/\//.test(token)) token = 'https:' + token;
        if (/^https?:\/\//i.test(token)) {
          try {
            const u = new URL(token);
            if (u.hostname) hosts.add(u.hostname.toLowerCase());
          } catch {}
          continue;
        }
        token = token.replace(/^\*\.?/, '').replace(/:\d+$/, '').replace(/\/.*$/, '');
        if (token && token.includes('.') && /^[a-z0-9.-]+$/i.test(token)) {
          hosts.add(token.toLowerCase());
        }
      }
    }
  }

  return [...hosts].slice(0, 50);
}

/**
 * Extract external hostnames from script/link/asset tags in HTML.
 */
function extractAssetHosts(html) {
  const hosts = new Set();
  const re = /(?:href|src)\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) && hosts.size < 50) {
    let p = m[1];
    if (/^\/\//.test(p)) p = 'https:' + p;
    if (/^https?:\/\//i.test(p)) {
      try {
        const u = new URL(p);
        if (u.hostname) hosts.add(u.hostname.toLowerCase());
      } catch {}
    }
  }
  return [...hosts];
}

/** schema.org names from JSON-LD blocks (organization / author / publisher). */
function jsonLdNames(html) {
  const names = new Set();
  const re = /<script[^>]+type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  let blocks = 0;
  while ((m = re.exec(html)) && blocks < 5) {
    blocks++;
    try {
      const data = JSON.parse(m[1].trim());
      const walk = (node, depth) => {
        if (!node || depth > 4) return;
        if (Array.isArray(node)) return node.forEach((n) => walk(n, depth + 1));
        if (typeof node !== 'object') return;
        for (const key of ['name', 'legalName']) {
          if (typeof node[key] === 'string' && node[key].length < 120) names.add(node[key]);
        }
        for (const key of ['@graph', 'publisher', 'author', 'organization', 'creator']) {
          if (node[key]) walk(node[key], depth + 1);
        }
      };
      walk(data, 0);
    } catch {
      /* malformed JSON-LD is not our problem */
    }
  }
  return [...names].slice(0, 12);
}

function stripFormControls(chunk) {
  if (!chunk || typeof chunk !== 'string') return '';
  return chunk
    .replace(/<select\b[^>]*>[\s\S]*?<\/select>/gi, ' ')
    .replace(/<option\b[^>]*>[\s\S]*?<\/option>/gi, ' ')
    .replace(/<option\b[^>]*>/gi, ' ');
}

/* ------------------------------------------------------------------ *
 * AI-artefact flags — booleans only, weights live in lib/verify.js
 * ------------------------------------------------------------------ */

function aiFlags(html, assets) {
  const cleanHtml = stripFormControls(html);
  const joined = assets.join(' ');
  return {
    shadcn: /shadcn/i.test(joined) || /data-slot\s*=/.test(cleanHtml),
    tailwind4: /--tw-/.test(cleanHtml) || /tailwind/i.test(joined),
    lucide: /lucide/i.test(joined) || /lucide/i.test(cleanHtml),
    appRouter: /_next\/static\/chunks\/app\//.test(joined),
    v0Badge: /v0\.dev|v0\.app|built with v0/i.test(cleanHtml),
    lovableBadge: /lovable\.(?:dev|app)|built with lovable/i.test(cleanHtml),
    boltBadge: /(?:href|src)\s*=\s*["'][^"']*bolt\.new/i.test(cleanHtml) || /built with bolt/i.test(cleanHtml) || /bolt\.new/i.test(cleanHtml),
    replitBadge: /replit\.com\/@|replit\.dev|built with replit/i.test(cleanHtml),
    marblismBadge: /marblism\.com|built with marblism/i.test(cleanHtml),
    createXyzBadge: /(?:href|src)\s*=\s*["'][^"']*create\.xyz/i.test(cleanHtml) || /built with create(?:\.xyz)?/i.test(cleanHtml) || /create\.xyz/i.test(cleanHtml),
  };
}

/**
 * Explicit self-disclosure in the page itself ("zgrajeno s strojem",
 * "built with AI", "powered by GPT"). This is a *disclosure*, not a detection:
 * it is treated as support for an `ai` claim and deliberately NOT as a
 * contradiction of a human claim, because a studio may use AI for one section
 * and still call the site hand-built. See lib/verify.js.
 */
const SELF_DISCLOSURE = [
  /zgrajeno\s+s\s+strojem/i,
  /narejeno\s+z\s+umetno\s+inteligenco/i,
  /\bbuilt\s+with\s+(?:ai|gpt|claude|gemini|deepseek|llama|llm|cursor|v0|lovable|bolt|replit)\b/i,
  /\bmade\s+with\s+(?:ai|gpt|claude|gemini|deepseek|llama|cursor|v0|lovable|bolt|replit)\b/i,
  /\bpowered\s+by\s+(?:gpt|claude|gemini|deepseek|openai|anthropic|google ai|meta ai|mistral)\b/i,
];

function selfDeclaredAI(html) {
  const cleanHtml = stripFormControls(html);
  return SELF_DISCLOSURE.some((re) => re.test(cleanHtml));
}

function aiPhrases(html) {
  const cleanHtml = stripFormControls(html);
  const text = cleanHtml
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .toLowerCase();
  const hits = [];
  for (const p of ['empower', 'seamless', 'elevate', 'unlock the power', 'revolutionise', 'revolutionize']) {
    if (text.includes(p)) hits.push(p);
  }
  return hits.slice(0, 6);
}

/* ------------------------------------------------------------------ *
 * Optional public files (same-origin GET, small, bounded)
 * ------------------------------------------------------------------ */

const AGENT_FILES = [
  '/AGENTS.md',
  '/CLAUDE.md',
  '/GEMINI.md',
  '/.cursor/rules',
  '/.cursor/rules/main.mdc',
  '/.cursorrules',
  '/.windsurfrules',
  '/.clinerules',
  '/.github/copilot-instructions.md',
  '/humans.txt',
];

async function fetchText(rawRequest, url, limit) {
  try {
    const r = await rawRequest(url, { method: 'GET', maxRedirects: 1 });
    if (!r || r.status !== 200 || !r.body) return null;
    const body = String(r.body);
    if (body.length > limit) return null;
    if (/^\s*</.test(body)) return null; // HTML error page or soft 404
    return body;
  } catch {
    return null;
  }
}

/**
 * @param {object} deps { rawRequest }
 * @param {string} origin
 * @returns {Promise<{agentFiles:string[], humansTxt:string|null}>}
 */
async function fetchPublicFiles(deps, origin) {
  const found = [];
  let humans = null;
  for (const p of AGENT_FILES) {
    const text = await fetchText(deps.rawRequest, origin + p, 64 * 1024);
    if (!text) continue;
    if (p === '/humans.txt') humans = text.slice(0, MAX_TEXT);
    else found.push(p);
  }
  return { agentFiles: found, humansTxt: humans };
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

/**
 * @param {string} body      final HTML (already fetched)
 * @param {object} res       { url, headers }
 * @param {object} deps      { rawRequest } — omit to skip the extra GETs
 * @returns {Promise<object>} compact fingerprint for meta.build
 */
async function collect(body, res, deps) {
  const html = String(body || '');
  let origin = null;
  try {
    origin = res && res.url ? new URL(res.url).origin : null;
  } catch {
    origin = null;
  }
  const assets = assetPaths(html, origin);
  const cspHosts = extractCspHosts(res, html);
  const assetHosts = extractAssetHosts(html);

  const out = {
    platform: detectPlatform(html),
    generator: generators(html),
    ogSiteName: metaContent(html, 'og:site_name'),
    footerText: footerText(html),
    jsonLdNames: jsonLdNames(html),
    assets,
    cspHosts,
    assetHosts,
    flags: { ...aiFlags(html, assets), selfDeclaredAI: selfDeclaredAI(html) },
    aiPhrases: aiPhrases(html),
    agentFiles: [],
    humansTxt: null,
    collectedAt: new Date().toISOString(),
  };

  if (deps && typeof deps.rawRequest === 'function' && res && res.url) {
    try {
      const origin = new URL(res.url).origin;
      const extra = await fetchPublicFiles(deps, origin);
      out.agentFiles = extra.agentFiles;
      out.humansTxt = extra.humansTxt;
    } catch {
      /* optional enrichment only */
    }
  }

  return out;
}

module.exports = {
  collect,
  detectPlatform,
  aiFlags,
  aiPhrases,
  assetPaths,
  extractCspHosts,
  extractAssetHosts,
  jsonLdNames,
  footerText,
  selfDeclaredAI,
  SELF_DISCLOSURE,
  stripFormControls,
};
