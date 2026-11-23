'use strict';
/**
 * Shared finding factory helpers, severity weights, and legal-policy patterns.
 */

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

module.exports = {
  SEVERITY_WEIGHT,
  makeFinding,
  slug,
  POLICY_RULES,
  mkFor,
  mkA11y,
  mkPerf,
  mkEu,
  mkProbe,
  mkSeo,
};
