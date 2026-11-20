'use strict';
/**
 * Phase 5 — EU compliance deepening.
 *
 * Everything here is a *signal*, not legal advice. The report cites the
 * regulation so the operator can decide.
 *
 *   - TCF v2.2 / Google Consent Mode v2 detection
 *   - pre-consent tracker firing (does a tracker load before the banner?)
 *   - cookie audit table (every Set-Cookie classified)
 *   - EU AI Act (Reg. 2024/1689) transparency signals
 *   - DSA (Reg. 2022/2065) trader-information / notice-and-action signals
 *   - data residency / third-country transfer hints + DPA presence
 */

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function cookieFlags(setCookieHeader, cookieName) {
  const parts = setCookieHeader.split(';').map((p) => p.trim());
  const [nameVal] = parts;
  const flags = {
    name: cookieName || (nameVal || '').split('=')[0],
    secure: parts.some((p) => /^secure$/i.test(p)),
    httpOnly: parts.some((p) => /^httponly$/i.test(p)),
    sameSite: (parts.find((p) => /^samesite=/i.test(p)) || '').split('=')[1] || null,
    partitioned: parts.some((p) => /^partitioned$/i.test(p)),
    maxAge: (parts.find((p) => /^max-age=/i.test(p)) || '').split('=')[1] || null,
    expires: (parts.find((p) => /^expires=/i.test(p)) || '').split('=').slice(1).join('=') || null,
    domain: (parts.find((p) => /^domain=/i.test(p)) || '').split('=')[1] || null,
    path: (parts.find((p) => /^path=/i.test(p)) || '').split('=')[1] || null,
  };
  const known = /^(_ga|_gid|_gcl|_fbp|_fbc|_hjid|_hj|ajs_|amplitude|mp_|_pk_|IDE|NID|__utm)/i;
  flags.kind = known.test(flags.name)
    ? 'analytics/marketing'
    : /(?:sess|sid|auth|token|jwt|login|csrf)/i.test(flags.name)
      ? 'session/auth'
      : /(?:consent|cookie|cc_|gdpr|tcf)/i.test(flags.name)
        ? 'consent'
        : 'other';
  return flags;
}

/* ------------------------------------------------------------------ *
 * Main entry
 * ------------------------------------------------------------------ */

function checkEuCompliance(body, res, findings, meta, peripherals, mk) {
  const html = body || '';
  const text = html.toLowerCase();
  const out = [];
  meta = meta || {};

  // When request was intercepted by a Cloudflare / WAF challenge page,
  // do not evaluate the challenge wrapper for compliance findings.
  if (meta && meta.isWafChallenge) return out;

  /* ---- Cookie parsing (available for consent & audit) -------------- */

  const setCookies = res.headers && res.headers['set-cookie']
    ? (Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : [res.headers['set-cookie']])
    : [];
  const cookieTable = setCookies.map((sc) => cookieFlags(sc));
  meta.eu = meta.eu || {};
  meta.eu.cookies = cookieTable;

  /* ---- 1. Consent framework depth ---------------------------------- */

  const frameworks = [];
  if (/__tcfapi|tcfapi\(|cmp\.|consentmanager|usercentrics|onetrust|cookiebot|klaro|osano|didomi|privacy-center\.org|spcloader|termly|app\.termly\.io/i.test(html)) {
    frameworks.push('CMP detected');
  }
  const tcf = /__tcfapi|tcfapi\(|iubenda|quantcast|didomi|sourcepoint|privacy-center\.org/i.test(html);
  if (tcf) frameworks.push('TCF v2.2 (IAB)');
  const consentMode = /gtag\(['"]consent|consent['"]\s*:\s*['"]default|gtm\.setConsent|consent_mode/i.test(html) ||
                       /consent-default|analytics_storage|ad_storage|ad_user_data|ad_personalization/i.test(html);
  if (consentMode) frameworks.push('Google Consent Mode v2');
  meta.eu.consentFrameworks = frameworks;

  const hasAnyConsentSignal = frameworks.length > 0 ||
    /cookie[-_ ]?consent|cookiebanner|cookie-banner|accept cookies|we use cookies|essential cookies|non-essential cookies|with your consent|preferences.*decline.*accept|nastavitve piškotkov|piškotki|termly|app\.termly\.io|type=["'](?:didomi\/javascript|text\/plain)/i.test(html);

  if (!hasAnyConsentSignal) {
    const hasTrackers = (meta.trackers || []).length > 0 ||
      /gtag\(|googletagmanager|facebook\.net\/.*fbevents|hotjar|clarity\.ms|matomo|plausible|umami/i.test(html);
    const alreadyFlagged = (findings || []).some((f) => f.id === 'no-consent' || f.id === 'eu-no-cmp');
    if (hasTrackers && !alreadyFlagged) {
      out.push(mk('eu-no-cmp', 'high', 'Trackers load before user consent ("Ghost Banner" / Prior Consent violation)',
        'GDPR Art. 6–7 + ePrivacy Art. 5(3) — non-essential cookies/identifiers load immediately without prior consent or Consent Mode gating. Even if a consent banner is displayed visually, firing trackers before the user opts in violates GDPR prior-consent mandates.',
        'Install a CMP that blocks non-essential scripts until opt-in, or configure Google Consent Mode v2 starting with all storage types defaulting to "denied".'));
    } else if (cookieTable.length > 0 && !alreadyFlagged) {
      out.push(mk('eu-no-cmp', 'info', 'No consent-management framework detected',
        'ePrivacy Art. 5(3) — cookies are set without a detected consent framework. If these cookies are non-essential, prior consent is legally required.',
        'If cookies are strictly necessary (e.g. auth/session), document this in your privacy policy. Otherwise, install a CMP to gate them.'));
    }
    // Note: When cookies.length === 0 and trackers.length === 0, the site is legally exempt from ePrivacy Art. 5(3) consent banners.
  }

  // Consent Mode v2 defaults must *deny* before the user chooses.
  if (consentMode) {
    const hasDenyDefault =
      /(?:analytics_storage|ad_storage)['"]?\s*:\s*['"]denied['"]/i.test(html) ||
      /(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*['"]denied['"][\s\S]{0,300}?(?:analytics_storage|ad_storage)['"]?\s*:\s*\1/i.test(html);
    if (!hasDenyDefault) {
      out.push(mk('eu-consent-mode-default', 'medium', 'Consent Mode is not defaulting to denied',
        'EDPB guidance + Google Consent Mode v2 — storage must start `denied` and only be granted after the user opts in. Starting granted leaks data pre-consent.',
        'Emit a consent default with analytics_storage:"denied", ad_storage:"denied", ad_user_data:"denied", ad_personalization:"denied" before any tag fires.'));
    }
  }

  // EDPB Cookie Banner Taskforce: Equal "Reject All" button at first layer (Dark Patterns).
  // Clean HTML by stripping script and style tags so Schema.org JSON-LD attributes
  // (e.g. "acceptedAnswer", "paymentAccepted") are never mistaken for consent buttons.
  const cleanHtml = html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '');

  const hasActualBanner = frameworks.length > 0 ||
    /id=["'](?:cookie[-_ ]?(?:banner|consent|notice|law|dialog|modal)|cmpbox|onetrust-banner-sdk)/i.test(cleanHtml) ||
    /class=["'][^"']*\b(?:cookie[-_ ]?(?:banner|consent|notice|law|bar|popup)|cc-window|cky-consent-container|didomi-popup)\b/i.test(cleanHtml);

  if (hasActualBanner) {
    const hasAccept = /\b(?:sprejmi(?: vse)?|accept(?: all)?|strinjam se|allow all|enable all|dovoli vse)\b/i.test(cleanHtml);
    const hasReject = /\b(?:zavrni(?: vse)?|reject(?: all)?|odkloni(?: vse)?|decline(?: all)?|disagree|refuse(?: all)?|odvrzi|ne dovoli)\b/i.test(cleanHtml);
    if (hasAccept && !hasReject) {
      out.push(mk('eu-cookie-no-reject-button', 'high', 'Cookie banner lacks an equal single-click "Reject All" option',
        'EDPB Cookie Banner Taskforce Report (2024–2026) — refusing cookies must be as easy and direct as accepting them, on the exact same layer. Hiding refusal behind a secondary "Settings" or "Manage" modal constitutes an unlawful dark pattern under GDPR Art. 4(11) & Art. 7(3).',
        'Add a visible "Zavrni vse" / "Reject All" button directly next to the accept button on the first layer of the consent banner.'));
    }
  }

  // Pre-ticked consent checkboxes (GDPR Art. 4(11), 7(4) + CJEU Planet49 C-673/17)
  const inputTags = html.match(/<input\b[^>]*>/gi) || [];
  const preticked = inputTags.filter((t) => {
    const typeMatch = t.match(/\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
    const type = (typeMatch ? (typeMatch[1] || typeMatch[2] || typeMatch[3]) : 'text').toLowerCase();
    if (type !== 'checkbox') return false;
    const isChecked = /\bchecked(?:\s*=\s*|\s|>|$)/i.test(t);
    if (!isChecked) return false;
    const nameMatch = t.match(/\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
    const idMatch = t.match(/\bid\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
    const valMatch = t.match(/\bvalue\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
    const attrText = `${nameMatch ? (nameMatch[1]||nameMatch[2]||nameMatch[3]) : ''} ${idMatch ? (idMatch[1]||idMatch[2]||idMatch[3]) : ''} ${valMatch ? (valMatch[1]||valMatch[2]||valMatch[3]) : ''}`.toLowerCase();
    return /(?:newsletter|novice|marketing|promocij|ponudb|obvescanj|soglasje|privolitv|gdpr|consent|third[-_ ]?party|partner)/i.test(attrText);
  });
  if (preticked.length) {
    out.push(mk('eu-preticked-consent', 'medium', `${preticked.length} pre-ticked consent checkbox(es) detected`,
      'GDPR Art. 4(11), Art. 7(4) & CJEU Planet49 (C-673/17) — consent must be freely given, specific, informed, and unambiguous. Pre-ticked checkboxes for marketing, newsletter subscriptions, or third-party data sharing do not constitute valid legal consent under EU law.',
      'Ensure all consent and newsletter checkboxes default to unchecked (opt-in), requiring active user affirmation.'));
  }

  /* ---- 2. Pre-consent tracker firing ------------------------------- */

  const isTagGated = (text) => /type\s*=\s*["'](?:text\/plain|didomi\/javascript|text\/consent|text\/cookiebot|optanon-category|text\/usercentrics)/i.test(text);
  const scriptBlocks = html.match(/<script\b[^>]*>[\s\S]*?<\/script>/gi) || [];

  const preConsent = [];
  const gtmBlocks = scriptBlocks.filter((b) => /googletagmanager\.com\/gtm\.js|google-analytics\.com\/analytics\.js/i.test(b));
  if (gtmBlocks.some((b) => !isTagGated(b)) && !consentMode) {
    preConsent.push('Google Analytics / GTM loaded inline');
  }

  const fbBlocks = scriptBlocks.filter((b) => /connect\.facebook\.net[^^\n]{0,80}fbevents|fbq\(['"]init/i.test(b));
  if (fbBlocks.some((b) => !isTagGated(b)) && !consentMode) {
    preConsent.push('Meta Pixel initialised inline');
  }

  // Session replay spyware (keystroke / DOM capture)
  // Exclude state hydration blocks (e.g. __INITIAL_STATE__, __NEXT_DATA__) which merely contain configuration flags.
  const replayBlocks = scriptBlocks.filter((b) => !/__INITIAL_STATE__|__NEXT_DATA__/i.test(b) && /(?:static\.hotjar\.com|script\.hotjar\.com|\._hjSettings|clarity\.ms\/tag|cdn\.fullstory\.com|rec\.smartlook\.com|cdn\.mouseflow\.com)/i.test(b));
  if (replayBlocks.some((b) => !isTagGated(b)) && !consentMode) {
    preConsent.push('Session replay tracker (Clarity/Hotjar/FullStory) loaded pre-consent');
    out.push(mk('privacy-session-replay', 'high', 'Session replay tracker active without prior consent / wiretap notice',
      'California Invasion of Privacy Act (CIPA § 631) & GDPR Art. 5(1)(c) — session replay tools record DOM mutations, mouse movements, and user keystrokes in real time. Deploying session replay without prior affirmative consent or conspicuous wiretapping disclosure creates severe class-action litigation exposure under CIPA and regulatory sanctions under GDPR.',
      'Gate session replay scripts behind explicit, prior opt-in consent (e.g. type="text/plain" in your CMP) and ensure sensitive form fields have data-private/data-mask attributes enabled.'));
  }

  const thirdPartyBlocks = scriptBlocks.filter((b) => !/__INITIAL_STATE__|__NEXT_DATA__/i.test(b) && /(?:googletagmanager\.com\/(?:gtm|gtag)\.js|google-analytics\.com\/analytics\.js|connect\.facebook\.net|static\.hotjar\.com|clarity\.ms\/tag)/i.test(b));
  if (thirdPartyBlocks.length && thirdPartyBlocks.some((b) => !isTagGated(b)) && !consentMode) {
    preConsent.push('third-party tag block is not consent-gated (missing type="text/plain" or CMP type)');
  }

  if (preConsent.length) {
    out.push(mk('eu-pre-consent-firing', 'high', `${preConsent.length} tracker(s) appear to fire before consent`,
      'ePrivacy Art. 5(3) — reading or writing data on the user\'s device requires consent *before* the tag runs. Blocking after load is not compliant.',
      'Load tracking scripts with type="text/plain" (or via your CMP\'s API) and only inject them after opt-in.',
      preConsent.join('\n')));
  }

  /* ---- 3. Cookie audit table -------------------------------------- */

  // Excessive cookie duration (> 13 months / 34,164,000s)
  const excessiveDuration = cookieTable.filter((c) => c.maxAge && Number(c.maxAge) > 34164000);
  if (excessiveDuration.length) {
    out.push(mk('eu-cookie-excessive-duration', 'low', `${excessiveDuration.length} cookie(s) exceed 13-month lifespan ceiling`,
      'EDPB and national DPA (CNIL) guidelines establish a maximum cookie lifespan of 13 months for tracking/analytics cookies. Longer durations violate GDPR Art. 5(1)(e) data minimisation.',
      'Set Set-Cookie Max-Age to <= 34164000 (13 months).',
      excessiveDuration.map((c) => `${c.name}: max-age=${c.maxAge}s (${Math.round(Number(c.maxAge)/86400)} days)`).join('\n')));
  }

  const thirdPartyCookies = cookieTable.filter((c) => c.domain && !String(res.url || '').includes(c.domain.replace(/^\./, '')));
  if (thirdPartyCookies.length) {
    out.push(mk('eu-third-party-cookie', 'medium', `${thirdPartyCookies.length} third-party cookie(s) set`,
      'GDPR Art. 44 + ePrivacy — cookies set on a registrable domain you do not own imply a third-country/third-party transfer that needs a legal basis.',
      'Either proxy/first-party the integration, or document the transfer and obtain consent before it fires.',
      thirdPartyCookies.map((c) => `${c.name} → domain=${c.domain}`).join('\n')));
  }

  /* ---- 4. EU AI Act transparency ---------------------------------- */

  const aiSignals = [];
  // Only detect actual embedded AI chat engines or interactive chat inputs,
  // NOT bare body copy or navigation links selling AI services.
  const hasAiChatEmbed = /(?:voiceflow\.com|botpress\.com|chatbase\.co|dify\.ai|ada\.cx)/i.test(html) ||
    /<(?:div|section|aside)\b[^>]*(?:id|class)=["'][^"']*\b(?:ai-chat|chatbot-widget|ai-assistant-widget)\b[^"']*["']/i.test(html) ||
    /<input\b[^>]*placeholder=["'][^"']*(?:ask ai|vprašaj ai|chat with ai)\b[^"']*["']/i.test(html);
  if (hasAiChatEmbed) {
    aiSignals.push('AI chat/assistant interface');
  }
  const aiDisclosure = /ai act|artificial intelligence act|automat(?:ed|ically) (?:system|decision)|human (?:agent|operator|oversight)|not a (?:human|real person)/i.test(html);

  meta.eu.ai = { signals: aiSignals, disclosed: aiDisclosure };
  if (aiSignals.length && !aiDisclosure) {
    out.push(mk('eu-ai-act-disclosure', 'medium', `AI system in use without an AI Act disclosure (${aiSignals.join(', ')})`,
      'EU AI Act (Reg. 2024/1689) Art. 50 — users must be told when they are interacting with an AI system, and AI-generated content must be machine-readably marked.',
      'Add a visible notice ("You are chatting with an AI assistant") and mark generated media with the appropriate metadata.',
      aiSignals.join('\n')));
  }

  /* ---- 5. DSA trader information / notice-and-action -------------- */

  // Strip CSS styles, script tags, and comments before analyzing textual content/affordances.
  // This prevents false positives from CSS class names (e.g. Divi's .et-cart-info matching \bcart\b),
  // script embeds, and code comments.
  const cleanBodyText = html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');

  const dsaSignals = [
    ['trader information (impressum / legal notice)', /impressum|legal notice|company (?:details|information)|vat id|vat number|matična številka|matična št|podjetje|zavod|davčna številka|davčna št/i],
    ['terms of service', /\bterms (?:of (?:service|use)|and conditions)\b|pogoji (?:poslovanja|in vračila|uporabe)/i],
    ['privacy policy', /privacy policy|politika zasebnosti|pravilnik o zasebnosti|zasebnost/i],
    ['report/notice-and-action route', /report (?:content|illegal|abuse)|prijavi vsebino|notice and action/i],
  ];
  const dsaFound = dsaSignals.filter(([, re]) => re.test(cleanBodyText)).map(([n]) => n);
  meta.eu.dsa = dsaFound;

  // Require a real transactional affordance in visible page content.
  // Avoid bare words like "buy", "cart", or "naročite" (which match "naročite se na e-novice",
  // "how to buy", or CSS class names). Match explicit e-commerce action phrases.
  const commercey = /(?:add to (?:cart|basket)|shopping[- ]cart|v košarico|\bcheckout\b|buy now|order now|kupi zdaj|na blagajno)\b/i.test(cleanBodyText);
  if (commercey) {
    const missing = [];
    if (!dsaFound.includes('trader information (impressum / legal notice)')) missing.push('trader identity (name, address, VAT/registration number)');
    if (!dsaFound.includes('terms of service')) missing.push('terms of service');
    if (missing.length) {
      out.push(mk('eu-dsa-trader-info', 'medium', `Online-sales page is missing DSA trader information (${missing.join(', ')})`,
        'EU Digital Services Act (Reg. 2022/2065) Art. 30–31 & E-Commerce Directive (2000/31/EC) Art. 5 — online marketplaces and B2C sellers must display trader traceability information before the order.',
        'Publish a legal notice with the trader\'s name, registered address and registration/VAT number, plus your terms.',
        missing.join('\n')));
    }
  }

  /* ---- 6. Data residency & DPA -------------------------------- */

  const thirdCountries = [];
  const map = [
    ['Google (US)', /google-analytics\.com|googletagmanager\.com|gtag\(/i],
    ['Meta (US)', /connect\.facebook\.net|facebook\.com\/tr/i],
    ['Cloudflare (US/global)', /static\.cloudflareinsights\.com|cdnjs\.cloudflare\.com/i],
    ['Amazon AWS (US/global)', /amazonaws\.com|cloudfront\.net/i],
    ['Microsoft (US)', /clarity\.ms|microsoft\.com|azure/i],
    ['Stripe (US/IE)', /js\.stripe\.com|stripe\.com/i],
    ['Vercel (US)', /vercel\.com|vercel-scripts\.com/i],
    ['Hotjar (MT)', /hotjar\.com/i],
  ];
  for (const [name, re] of map) if (re.test(html)) thirdCountries.push(name);
  meta.eu.thirdCountries = thirdCountries;

  const combinedCorpus = [html, ...((meta && meta._policyCorpus) || [])].join('\n');
  const hasLegalLinkWithConsent = consentMode && /href\s*=\s*["'][^"']*(?:legal|privacy|zasebnost|pogoji|impressum|gdpr)/i.test(combinedCorpus);
  const dpaMention = hasLegalLinkWithConsent || /data processing agreement|dpa\b|standard contractual clauses|\bsccs?\b|transfer impact assessment|schrems|data privacy framework|\bdpf\b|google consent mode|izrecn[oi] privolitv|tretjim osebam|pogodben[a-z]* obdeloval|varstvo osebnih podatkov|never shared or tracked|stored privately on our server/i.test(combinedCorpus);
  if (thirdCountries.length && !dpaMention) {
    out.push(mk('eu-data-transfer', 'low', `${thirdCountries.length} third-country processor(s) with no documented transfer mechanism`,
      'GDPR Art. 44–46 — transfers outside the EEA require an adequacy decision or SCCs plus a transfer impact assessment, referenced in your privacy policy.',
      'Name each processor in the privacy policy and state the safeguard (adequacy / SCCs / DPF).',
      thirdCountries.join(', ')));
  }

  /* ---- 7. US Privacy Mosaic (CCPA/CPRA, TDPSA, GPC) ---------------- */

  const hasMarketingOrAnalytics = (meta.trackers || []).length > 0 ||
    /(?:googletagmanager\.com|google-analytics\.com|connect\.facebook\.net|analytics\.tiktok\.com|snap\.licdn\.com|doubleclick\.net|criteo\.com|outbrain\.com|taboola\.com)/i.test(html);

  if (hasMarketingOrAnalytics) {
    const hasUsOptOut = /(?:do not sell|do not share|your privacy choices|california privacy rights|opt-out preference|global privacy control|\bsec-gpc\b)/i.test(cleanHtml);
    if (!hasUsOptOut && !frameworks.some((f) => /onetrust|usercentrics|osano|trustarc|termly/i.test(f))) {
      out.push(mk('us-gpc-optout', 'medium', 'Missing "Do Not Sell/Share" or GPC opt-out mechanism for US privacy laws',
        'California CCPA/CPRA (Civ. Code § 1798.135), Texas TDPSA, Colorado CPA & Connecticut CTDPA — websites deploying third-party advertising, analytics, or trackers must provide a conspicuous "Do Not Sell or Share My Personal Information" or "Your Privacy Choices" link and honor automated Global Privacy Control (GPC) opt-out preference signals.',
        'Add a visible "Your Privacy Choices" or "Do Not Sell or Share My Personal Information" link in your global footer, and configure your CMP or tag manager to automatically honor the Sec-GPC: 1 request header and navigator.globalPrivacyControl signal.'));
    }
  }

  /* ---- 8. Tracker → consent ratio sanity -------------------------- */

  const trackerCount = (meta.trackers || []).length;
  if (trackerCount >= 3 && !hasAnyConsentSignal) {
    // already covered by eu-no-cmp, but escalate severity is handled there.
  }

  /* ---- 8. EU accessibility cross-link ----------------------------- */

  if (meta.a11y && meta.a11y.statement === false) {
    // a11y module owns this finding; nothing to duplicate.
  }

  return out;
}

module.exports = { checkEuCompliance, cookieFlags };
