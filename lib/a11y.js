'use strict';
/**
 * Phase 4 — Accessibility (WCAG 2.2 AA / EU Accessibility Act).
 *
 * Two passes:
 *   - checkA11yStatic(html)   — works on raw HTML, no browser needed.
 *   - checkA11yRendered(dom)  — works on the post-JS DOM + computed styles
 *                               (contrast results are injected by webvitals).
 *
 * Every check maps to a WCAG 2.2 success criterion so the report can cite it.
 */

/* ------------------------------------------------------------------ *
 * Tiny HTML helpers (deliberately regex-based — no DOM dependency)
 * ------------------------------------------------------------------ */

function tags(html, name) {
  return html.match(new RegExp(`<${name}\\b[^>]*>`, 'gi')) || [];
}

function attr(tag, name) {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i'));
  if (!m) return null; // absent
  return (m[1] ?? m[2] ?? m[3] ?? ''); // '' when present but empty
}

/**
 * Boolean-attribute presence test. `attr()` only matches `name="value"`, so it
 * reports bare flags like `autoplay`, `muted` or `disabled` as absent — that
 * masked autoplay-with-sound (WCAG 1.4.2). This matches the attribute when it
 * appears either bare (`autoplay`) or with a value (`autoplay="autoplay"`).
 */
function hasAttr(tag, name) {
  return new RegExp(`\\b${name}(?:\\s*=|\\s|>|$)`, 'i').test(tag);
}

function textOf(html, name) {
  const m = html.match(new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)</${name}>`, 'i'));
  return m ? m[1].replace(/<[^>]+>/g, '').trim() : '';
}

/**
 * Is THIS specific control wrapped inside a <label> element?
 *
 * Previously this was a single page-wide regex tested once per input, so a
 * page containing *any* <label>…<input> pair marked every field as labelled
 * and masked the genuinely unlabelled ones (false negative). Locate the tag
 * in the document and decide by comparing the nearest preceding <label> open
 * vs </label> close, which also covers labels that are never closed.
 */
function isWrappedInLabel(html, tag, occurrence = 0) {
  let from = 0;
  let idx = -1;
  for (let i = 0; i <= occurrence; i++) {
    idx = html.indexOf(tag, from);
    if (idx < 0) return false;
    from = idx + 1;
  }
  const before = html.slice(0, idx).toLowerCase();
  const openIdx = before.lastIndexOf('<label');
  if (openIdx < 0) return false;
  return openIdx > before.lastIndexOf('</label>');
}

function hasAffirmativeFocus(css) {
  const blocks = css.match(/:focus(?:-visible)?\s*\{[^}]+\}/gi) || [];
  for (const block of blocks) {
    const inner = block.replace(/^[^{]*\{|\}$/g, '');
    const decls = inner.split(';').map((d) => d.trim().toLowerCase());
    for (const d of decls) {
      const [prop, val] = d.split(':').map((s) => (s || '').trim());
      if (prop === 'outline' && val && !['none', '0', 'transparent'].includes(val)) return true;
      if (['outline-width', 'outline-style', 'outline-color', 'outline-offset'].includes(prop)) return true;
      if (prop === 'box-shadow' && val && !['none', '0'].includes(val)) return true;
      if (prop && prop.startsWith('border') && val && !['none', '0'].includes(val)) return true;
    }
  }
  return false;
}

/* ------------------------------------------------------------------ *
 * Static (raw-HTML) checks
 * ------------------------------------------------------------------ */

function checkA11yStatic(html, findings, meta, mk) {
  if (meta && meta.isWafChallenge) return [];
  meta.a11y = meta.a11y || {};
  const out = [];

  // 1.3.1 / 4.1.2 — form controls need an accessible name.
  const inputs = [...tags(html, 'input'), ...tags(html, 'select'), ...tags(html, 'textarea')];
  const unlabeled = [];
  const unlabeledTags = [];
  const seenTags = new Map();
  for (const t of inputs) {
    const type = (attr(t, 'type') || 'text').toLowerCase();
    if (['hidden', 'submit', 'button', 'reset', 'image'].includes(type)) continue;
    // Skip hidden or anti-spam honeypot controls (aria-hidden, hidden attr, opacity:0 + pointer-events:none, tabindex=-1 honeypots)
    if (hasAttr(t, 'hidden') || String(attr(t, 'aria-hidden') || '').toLowerCase() === 'true') continue;
    const fName = attr(t, 'name') || attr(t, 'id') || '';
    const fStyle = attr(t, 'style') || '';
    if (/(?:^hp_|honeypot|cf-turnstile-response|g-recaptcha-response|h-captcha-response)/i.test(fName)) continue;
    if (/display\s*:\s*none|visibility\s*:\s*hidden/i.test(fStyle)) continue;
    if (/opacity\s*:\s*0\b/i.test(fStyle) && (/pointer-events\s*:\s*none/i.test(fStyle) || attr(t, 'tabindex') === '-1')) continue;
    const aria = attr(t, 'aria-label') || attr(t, 'aria-labelledby');
    const id = attr(t, 'id');
    // Anchor the `for` value at its end: an unanchored match lets a control
    // with id="1" be considered labelled by an unrelated <label for="12">
    // (or for="1abc"), hiding genuinely unlabelled fields (WCAG 1.3.1).
    // `attr()` returns null when the attribute is absent, so `id` may be null
    // for any control that has no id — the common case for plain <input>, so
    // this must be guarded or the entire static pass throws and produces zero
    // findings (silent loss of every a11y check).
    const idEsc = (id || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const hasLabel = id
      ? new RegExp(`<label\\b[^>]*\\bfor\\s*=\\s*(?:"${idEsc}"|'${idEsc}'|${idEsc}(?=[\\s>/]))`, 'i').test(html)
      : false;
    const occ = seenTags.get(t) || 0;
    seenTags.set(t, occ + 1);
    const wrapped = isWrappedInLabel(html, t, occ);
    if (!aria && !hasLabel && !wrapped) {
      unlabeled.push(id ? '#' + id : (attr(t, 'name') || '(unnamed)'));
      unlabeledTags.push(t.replace(/\s+/g, ' ').trim().slice(0, 240));
    }
  }
  if (unlabeled.length) {
    const f = mk('a11y-label', 'medium', `${unlabeled.length} form field(s) without a label`,
      'WCAG 2.2 · 1.3.1 / 4.1.2 — every control needs a programmatic name. Screen-reader and voice-control users cannot fill these in.',
      'Associate a <label for="id"> or add aria-label / aria-labelledby.',
      unlabeledTags.length ? unlabeledTags.slice(0, 10).join('\n') : unlabeled.slice(0, 10).join(', '));
    f.locations = unlabeled.slice(0, 12).map((label, i) => ({
      selector: label.startsWith('#') ? label : null,
      html: unlabeledTags[i] || null,
    }));
    out.push(f);
  }

  // 1.4.4 — user-scalable=no / maximum-scale=1 blocks pinch-zoom.
  const viewport = (html.match(/<meta\b[^>]*name\s*=\s*["']?viewport["']?[^>]*>/i) || [''])[0];
  const vpContent = attr(viewport, 'content') || '';
  if (/user-scalable\s*=\s*no/i.test(vpContent) || /maximum-scale\s*=\s*1(\.0)?\b/i.test(vpContent)) {
    out.push(mk('a11y-zoom', 'medium', 'Pinch-zoom is disabled',
      'WCAG 2.2 · 1.4.4 — `user-scalable=no` / `maximum-scale=1` prevents low-vision users from magnifying content.',
      'Remove user-scalable and maximum-scale from the viewport meta tag.'));
  }

  // 3.1.1 — <html lang>.
  const htmlTag = (html.match(/<html\b[^>]*>/i) || [''])[0];
  if (!attr(htmlTag, 'lang')) {
    out.push(mk('a11y-lang', 'medium', 'Page language is not declared',
      'WCAG 2.2 · 3.1.1 — without <html lang>, screen readers guess pronunciation and may read the page in the wrong language.',
      'Set <html lang="en"> (or the correct BCP-47 tag).'));
  }

  // 3.3.2 — inputs should carry autocomplete for personal data.
  const personal = /name|email|tel|phone|address|postal|zip|cc-|password|username|given|family/i;
  const nonTextTypes = new Set(['hidden', 'submit', 'reset', 'button', 'image', 'checkbox', 'radio', 'file', 'color', 'range']);
  const noAutocomplete = inputs.filter((t) => {
    const type = (attr(t, 'type') || 'text').toLowerCase();
    if (nonTextTypes.has(type)) return false;
    if (attr(t, 'disabled') !== null || attr(t, 'readonly') !== null || attr(t, 'aria-hidden') === 'true') return false;
    const n = attr(t, 'name') || attr(t, 'id') || '';
    if (!personal.test(n) && !['password', 'email', 'tel'].includes(type)) return false;
    return attr(t, 'autocomplete') === null;
  });
  if (noAutocomplete.length) {
    out.push(mk('a11y-autocomplete', 'low', `${noAutocomplete.length} personal-data field(s) without autocomplete`,
      'WCAG 2.2 · 1.3.5 / 3.3.2 — autocomplete helps users with motor and cognitive disabilities fill forms.',
      'Add autocomplete="email" | "name" | "tel" | "street-address" | "current-password", etc.'));
  }

  // 2.4.1 — skip link.
  // Only applicable when the page actually has a multi-link navigation block to bypass.
  const navBlocks = html.match(/<nav\b[^>]*>[\s\S]*?<\/nav>/gi) || [];
  const navLinkCount = navBlocks.reduce((sum, nb) => sum + (nb.match(/<a\b/gi) || []).length, 0);
  const firstLink = (html.match(/<body\b[^>]*>([\s\S]{0,1600})/i) || [, ''])[1];
  const hasSkip = /<a\b[^>]*href\s*=\s*["']#(?:main|content|skip|primary)/i.test(firstLink) ||
                  /class\s*=\s*["'][^"']*skip/i.test(firstLink);
  const hasMainLandmark = /<main\b/i.test(html) || /role\s*=\s*["']main["']/i.test(html);
  if (!hasSkip && navLinkCount >= 3) {
    out.push(mk('a11y-skip-link', hasMainLandmark ? 'info' : 'low', 'No skip-to-content link',
      'WCAG 2.2 · 2.4.1 — keyboard users must tab through the whole nav on every page.',
      'Add a visually-hidden "Skip to main content" link as the first focusable element.'));
  }

  // 2.4.2 — title already covered by SEO, but flag empty.
  if (!textOf(html, 'title')) {
    out.push(mk('a11y-title', 'medium', 'Missing or empty <title>',
      'WCAG 2.2 · 2.4.2 — every page needs a descriptive title for orientation.',
      'Add a unique, descriptive <title>.'));
  }

  // 2.4.6 / 1.3.1 — heading structure.
  const h1s = tags(html, 'h1');
  if (h1s.length === 0) {
    out.push(mk('a11y-h1', 'medium', 'No <h1> heading',
      'WCAG 2.2 · 1.3.1 — the page has no top-level heading, so its outline is ambiguous.',
      'Use exactly one <h1> that describes the page.'));
  } else if (h1s.length > 1) {
    out.push(mk('a11y-h1-multi', 'low', `${h1s.length} <h1> headings`,
      'WCAG 2.2 · 1.3.1 — multiple top-level headings flatten the document outline.',
      'Keep a single <h1>; demote the rest to <h2>.'));
  }
  const order = [...html.matchAll(/<h([1-6])\b/gi)].map((m) => +m[1]);
  for (let i = 1; i < order.length; i++) {
    if (order[i] - order[i - 1] > 1) {
      out.push(mk('a11y-heading-order', 'low', 'Heading levels are skipped',
        `WCAG 2.2 · 1.3.1 — heading jumps from h${order[i - 1]} to h${order[i]}. That breaks non-visual navigation.`,
        'Never skip heading levels; go h2 → h3, not h2 → h4.'));
      break;
    }
  }

  // 2.4.4 — ambiguous link text.
  const linkMatches = [...html.matchAll(/<a\b[^>]*>([\s\S]*?)<\/a>/gi)];
  const linkTexts = linkMatches
    .map((m) => m[1].replace(/<[^>]+>/g, '').trim().toLowerCase())
    .filter((t) => t.length > 0);
  const vague = ['click here', 'here', 'read more', 'more', 'link', 'this', 'learn more', 'details'];
  const vagueHits = linkTexts.filter((t) => vague.includes(t));
  if (vagueHits.length >= 2) {
    const vagueTags = linkMatches
      .filter((m) => vague.includes(m[1].replace(/<[^>]+>/g, '').trim().toLowerCase()))
      .slice(0, 10)
      .map((m) => m[0].replace(/\s+/g, ' ').trim().slice(0, 240));
    const f = mk('a11y-link-text', 'low', `${vagueHits.length} non-descriptive link(s)`,
      'WCAG 2.2 · 2.4.4 — "click here" gives screen-reader users no context when links are listed out of order.',
      'Describe the destination: "View pricing", "Download the 2026 report".',
      vagueTags.join('\n'));
    if (vagueTags.length) f.locations = vagueTags.map((h) => ({ html: h }));
    out.push(f);
  }

  // 2.2.2 — auto-playing media.
  const media = [...tags(html, 'video'), ...tags(html, 'audio')];
  const autoplay = media.filter((t) => hasAttr(t, 'autoplay') && !hasAttr(t, 'muted'));
  if (autoplay.length) {
    const f = mk('a11y-autoplay', 'medium', 'Media has autoplay without \'muted\' attribute',
      'WCAG 2.2 · 1.4.2 / 2.2.2 — <video>/<audio> declares "autoplay" without an explicit "muted" attribute. Even if silenced by browser autoplay policies, assistive tools treat unmuted autoplaying media as an audio obstruction.',
      'Add the `muted` attribute (e.g. <video autoplay muted playsinline>) and provide visible pause/stop controls.',
      autoplay.slice(0, 10).map((t) => t.replace(/\s+/g, ' ').trim().slice(0, 240)).join('\n'));
    f.locations = autoplay.slice(0, 12).map((t) => ({ html: t.replace(/\s+/g, ' ').trim().slice(0, 240) }));
    out.push(f);
  }

  // 1.3.1 / 2.4.1 — landmark regions.
  const mainLandmark = /<main\b/i.test(html) || /role\s*=\s*["']main["']/i.test(html);
  if (!mainLandmark) {
    out.push(mk('a11y-landmark', 'low', 'No <main> landmark',
      'WCAG 2.2 · 1.3.1 / 2.4.1 — landmark regions let assistive tech jump straight to the content.',
      'Wrap the primary content in a single <main> element.'));
  }

  // 4.1.2 — buttons vs links.
  // Only flag anchors that genuinely do not navigate: empty href, a bare "#",
  // or a javascript: pseudo-protocol. In-page fragment links (href="#section")
  // are legitimate navigation (skip-links, tables of contents) and must NOT be
  // reported as "links used as buttons".
  const jsLinks = tags(html, 'a').filter((t) => {
    const m = t.match(/href\s*=\s*["']([^"']*)["']/i);
    if (!m) return false;
    const href = m[1].trim();
    return href === '' || href === '#' || /^javascript:/i.test(href);
  });
  if (jsLinks.length >= 3) {
    out.push(mk('a11y-button-semantics', 'low', `${jsLinks.length} link(s) used as buttons`,
      'WCAG 2.2 · 4.1.2 — anchors that do not navigate confuse screen readers, which announce "link".',
      'Use <button> for actions and <a href> for navigation.'));
  }

  // 1.3.1 — tables without headers.
  const tables = tags(html, 'table');
  const th = tags(html, 'th');
  if (tables.length && th.length === 0) {
    out.push(mk('a11y-table-headers', 'medium', 'Data table without header cells',
      'WCAG 2.2 · 1.3.1 — screen readers cannot associate data cells with their column.',
      'Add <th scope="col|row"> to header cells.'));
  }

  // 2.4.7 / 1.4.11 — is there a visible focus ring? (static stylesheet check)
  const outlineNone = /outline\s*:\s*(?:none|0)/i.test(html);
  const affirmative = hasAffirmativeFocus(html);
  const hasUtilityFocus = /focus(?:-visible)?[:\w-]*(?:ring|border|outline)/i.test(html);
  if (outlineNone && !affirmative && !hasUtilityFocus) {
    const ruleHits = [...html.matchAll(/([^{}]*)\{[^{}]*outline\s*:\s*(?:none|0)[^{}]*\}/gi)]
      .map((m) => m[0].replace(/\s+/g, ' ').trim().slice(0, 300));
    const ev = ruleHits.length
      ? ruleHits.slice(0, 5).join('\n')
      : 'Found `outline: none` (or `outline: 0`) in the stylesheet with no :focus / :focus-visible replacement rule.';
    const f = mk('a11y-focus-visible', 'medium', 'Focus indicator removed',
      'WCAG 2.2 · 2.4.7 / 1.4.11 — `outline: none` with no replacement leaves keyboard users with no idea where they are.',
      'Provide a custom :focus-visible style (e.g. outline: 2px solid #4a9eff; outline-offset: 2px) or utility focus rings.',
      ev);
    if (ruleHits.length) f.locations = ruleHits.slice(0, 8).map((r) => ({ css: r }));
    out.push(f);
  }

  // EU Accessibility Act — is there an accessibility statement?
  const hasStatement = /accessibility[\s-]?statement|declaration\s*d['’]?accessibilit|izjava o dostopnosti/i.test(html);
  meta.a11y = meta.a11y || {};
  meta.a11y.statement = Boolean(hasStatement);
  if (!hasStatement) {
    out.push(mk('a11y-statement', 'info', 'No accessibility statement found',
      'EU Accessibility Act (28 Jun 2025) — EU-facing services must publish a statement describing conformance and a feedback route.',
      'Publish an accessibility statement with conformance level, known limitations and contact details.'));
  }

  meta.a11y.static = {
    inputs: inputs.length,
    images: tags(html, 'img').length,
    headings: order.length,
    links: linkTexts.length,
  };
  return out;
}

function isDecorativeOrHiddenImg(t) {
  const w = attr(t, 'width');
  const h = attr(t, 'height');
  if ((w !== null && parseInt(w, 10) <= 1) || (h !== null && parseInt(h, 10) <= 1)) return true;
  const style = (attr(t, 'style') || '').toLowerCase();
  if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b/.test(style)) return true;
  if (/width\s*:\s*[01]px|height\s*:\s*[01]px/.test(style)) return true;
  if (attr(t, 'aria-hidden') === 'true' || hasAttr(t, 'hidden')) return true;
  const src = (attr(t, 'src') || '').toLowerCase();
  if (/facebook\.com\/tr|\/tr\?id=|google-analytics\.com|doubleclick\.net|clarity\.ms|bat\.bing\.com|linkedin\.com\/px/i.test(src)) return true;
  return false;
}

/* ------------------------------------------------------------------ *
 * Rendered-DOM checks (needs headless Chrome)
 * ------------------------------------------------------------------ */

function checkA11yRendered(dom, contrast, findings, meta, mk) {
  const out = [];
  const html = dom || '';

  // 1.1.1 — alt text on the *rendered* DOM (catches JS-injected images).
  // Excludes 1x1 tracking pixels (Facebook Pixel, analytics beacons) and hidden elements per WCAG decorative image rules.
  const imgs = tags(html, 'img');
  const noAlt = imgs.filter((t) => attr(t, 'alt') === null && !isDecorativeOrHiddenImg(t));
  if (noAlt.length) {
    const f = mk('a11y-alt-rendered', 'medium', `${noAlt.length} image(s) without alt text (rendered DOM)`,
      'WCAG 2.2 · 1.1.1 — images injected by JS were missing from the static scan and have no text alternative.',
      'Give every content image a meaningful alt attribute; use alt="" only for decoration.',
      noAlt.slice(0, 10).map((t) => t.replace(/\s+/g, ' ').slice(0, 240)).join('\n'));
    f.locations = noAlt.slice(0, 12).map((t) => ({
      selector: attr(t, 'src') ? `img[src="${(attr(t, 'src') || '').slice(0, 120)}"]` : 'img',
      html: t.replace(/\s+/g, ' ').slice(0, 240),
    }));
    out.push(f);
  }

  // 1.4.3 / 1.4.11 — computed-style contrast.
  if (contrast && contrast.violations && contrast.violations.length) {
    // Filter out inactive / decorative / struck-through text per WCAG 1.4.3 exception
    const realViolations = contrast.violations.filter((v) => {
      const htmlLower = (v.html || '').toLowerCase();
      const selLower = (v.selector || '').toLowerCase();
      // Exclude struck-through discount prices or disabled/aria-hidden elements
      if (htmlLower.includes('line-through') || selLower.includes('line-through')) return false;
      if (htmlLower.includes('disabled') || htmlLower.includes('aria-hidden="true"')) return false;
      if (htmlLower.includes('<del') || htmlLower.includes('<s') || htmlLower.includes('<strike')) return false;
      return true;
    });

    if (realViolations.length) {
      const sample = realViolations.slice(0, 5)
        .map((v) => {
          const where = v.selector ? `\n    at ${v.selector}` : '';
          const snip = v.html ? `\n    ${v.html}` : '';
          return `${v.ratio}:1 (needs ${v.need}:1) ${v.fg} on ${v.bg} — "${v.text}"${where}${snip}`;
        });
      // Structured locators so the UI/export can link straight to the element.
      const locations = realViolations.slice(0, 12)
        .filter((v) => v.selector)
        .map((v) => ({ selector: v.selector, text: v.text, ratio: v.ratio, need: v.need, fg: v.fg, bg: v.bg, html: v.html || null }));
      
      const minRatio = Math.min(...realViolations.map((v) => (typeof v.ratio === 'number' ? v.ratio : 0)));
      // Proportional severity: systemic severe contrast failure (< 4.0:1 across >= 8 elements) is 'high';
      // near-threshold AA misses (all violations >= 4.0:1, e.g. 4.32:1) cap at 'medium'.
      const sev = (realViolations.length >= 8 && minRatio < 4.0) ? 'high' : (realViolations.length >= 3 ? 'medium' : 'low');
      const f = mk('a11y-contrast', sev, `${realViolations.length} low-contrast text element(s)`,
        `WCAG 2.2 · 1.4.3 — colour contrast is below the AA threshold. Measured against ${contrast.checked} element(s).`,
        'Darken the text or lighten the background until the ratio is ≥ 4.5:1 (≥ 3:1 for ≥ 24px / bold ≥ 18.66px).',
        sample.join('\n'));
      if (locations.length) f.locations = locations;
      out.push(f);
    }
  }

  // 2.4.7 / 1.4.11 — is there a visible focus ring?
  const outlineNone = /outline\s*:\s*(?:none|0)/i.test(html);
  const affirmative = hasAffirmativeFocus(html);
  const hasUtilityFocus = /focus(?:-visible)?[:\w-]*(?:ring|border|outline)/i.test(html);
  if (outlineNone && !affirmative && !hasUtilityFocus) {
    // Capture the offending declaration(s) with a little surrounding context so
    // the report shows the actual rule that removed the focus ring.
    const ruleHits = [...html.matchAll(/([^{}]*)\{[^{}]*outline\s*:\s*(?:none|0)[^{}]*\}/gi)]
      .map((m) => m[0].replace(/\s+/g, ' ').trim().slice(0, 300));
    const ev = ruleHits.length
      ? ruleHits.slice(0, 5).join('\n')
      : 'Found `outline: none` (or `outline: 0`) in the stylesheet with no :focus / :focus-visible replacement rule.';
    const f = mk('a11y-focus-visible', 'medium', 'Focus indicator removed',
      'WCAG 2.2 · 2.4.7 / 1.4.11 — `outline: none` with no replacement leaves keyboard users with no idea where they are.',
      'Provide a custom :focus-visible style (e.g. outline: 2px solid #4a9eff; outline-offset: 2px) or utility focus rings.',
      ev);
    if (ruleHits.length) f.locations = ruleHits.slice(0, 8).map((r) => ({ css: r }));
    out.push(f);
  }

  // 2.3.3 — animations with no reduced-motion fallback.
  const manyAnim = (html.match(/animation(?:-name)?\s*:\s*[^;]+;/gi) || []).length;
  const hasReducedMotion = /prefers-reduced-motion/i.test(html);
  if (manyAnim >= 4 && !hasReducedMotion) {
    out.push(mk('a11y-reduced-motion', 'low', `${manyAnim} CSS animations with no reduced-motion fallback`,
      'WCAG 2.2 · 2.3.3 — motion can trigger nausea, migraine and vestibular distress.',
      'Wrap animations in @media (prefers-reduced-motion: no-preference) and honour the user preference.'));
  }

  // 4.1.3 — status messages should be live regions (heuristic).
  // Exclude <svg> icons (e.g. Lucide `lucide-circle-alert` / `lucide-triangle-alert`),
  // Tailwind color utility tokens (`text-alert`, `border-alert`), and empty/hidden
  // placeholder containers (`<div class="error-msg"></div>` or `style="display:none"`).
  const TOAST_CLASS_RE = /\b(?:toast|toaster|alert|alert-box|alert-banner|notification|notification-bar|snackbar|error-msg|error-banner)\b/i;
  let toastish = false;
  if (TOAST_CLASS_RE.test(html)) {
    const scanHtml = html.length > 500_000 ? html.slice(0, 500_000) : html;
    const tagRe = /<((?!svg\b|path\b|circle\b|line\b|rect\b|g\b)[a-z0-9-]+)\b([^<>]{0,500})>([\s\S]{0,300}?)<\/\1>/gi;
    let m;
    while ((m = tagRe.exec(scanHtml)) !== null) {
      const attrs = m[2] || '';
      const inner = (m[3] || '').replace(/<[^>]+>/g, '').trim();
      if (!inner) continue;
      if (/display\s*:\s*none|visibility\s*:\s*hidden|\bhidden\b/i.test(attrs)) continue;
      const cm = attrs.match(/\bclass\s*=\s*["']([^"']*)["']/i);
      if (!cm) continue;
      const classes = cm[1].split(/\s+/);
      if (classes.some((cls) => /^(?:toast|toaster|alert|alert-box|alert-banner|notification|notification-bar|snackbar|error-msg|error-banner)$/i.test(cls))) {
        toastish = true;
        break;
      }
    }
  }
  const hasLive = /aria-live|role\s*=\s*["'](?:alert|status|log)["']/i.test(html);
  if (toastish && !hasLive) {
    out.push(mk('a11y-live-region', 'low', 'Dynamic messages are not announced',
      'WCAG 2.2 · 4.1.3 — toast/banner elements without aria-live are invisible to screen-reader users.',
      'Add role="status" or aria-live="polite" to non-critical banners.'));
  }

  // EU Accessibility Act — is there an accessibility statement?
  const hasStatement = (meta.a11y && meta.a11y.statement) || /accessibility[\s-]?statement|declaration\s*d['’]?accessibilit|izjava o dostopnosti/i.test(html);
  meta.a11y = meta.a11y || {};
  meta.a11y.statement = Boolean(hasStatement);
  if (!hasStatement && !findings.some((f) => f.id === 'a11y-statement') && !out.some((f) => f.id === 'a11y-statement')) {
    out.push(mk('a11y-statement', 'info', 'No accessibility statement found',
      'EU Accessibility Act (28 Jun 2025) — EU-facing services must publish a statement describing conformance and a feedback route.',
      'Publish an accessibility statement with conformance level, known limitations and contact details.'));
  } else if (hasStatement && findings) {
    for (let i = findings.length - 1; i >= 0; i--) {
      if (findings[i].id === 'a11y-statement') findings.splice(i, 1);
    }
  }

  meta.a11y.rendered = { images: imgs.length, contrastChecked: contrast ? contrast.checked : 0 };
  return out;
}

module.exports = { checkA11yStatic, checkA11yRendered, tags, attr };
