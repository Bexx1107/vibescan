'use strict';
/**
 * Scan integrity — guard against *silent* capability loss (P0).
 *
 * The problem this exists to kill:
 *
 *   If the headless renderer is missing (no Chrome), `webvitals.measure()`
 *   returns `{ ok:false }` and the scanner just moves on. The perf + rendered
 *   a11y checks then *contribute no findings* — and because the overall score
 *   is the mean of the per-domain scores, those empty domains pull the score
 *   **UP**. A site could score 97 precisely because the checks never ran.
 *
 * So: a scan that ran without its rendering capability is marked `degraded`,
 * which (a) is surfaced loudly in the report + `/api/health`, and (b) caps the
 * headline score so "unverified" can never masquerade as "excellent".
 *
 * Zero external dependencies.
 */

const deep = require('./deep');

/** The capabilities a full scan is expected to have. */
const RENDER_CAPABILITY = 'headless-render';
const HEADERS_UNVERIFIED_CAPABILITY = 'waf-headers-unverified';

/** A degraded scan can never grade above this (a hard "we could not verify"). */
const DEGRADED_SCORE_CAP = 79; // → grade C

/**
 * One-shot (cached) probe for the headless browser binary.
 * @returns {{ok:boolean, path:string|null, error:string|null, hint:string}}
 */
let _probe = null;
function probeRenderCapability({ fresh = false } = {}) {
  if (_probe && !fresh) return _probe;
  let chromePath = null;
  try {
    chromePath = deep.pickChrome();
  } catch (e) {
    chromePath = null;
  }
  _probe = chromePath
    ? { ok: true, path: chromePath, error: null, hint: null }
    : {
        ok: false,
        path: null,
        error: 'no headless browser binary found',
        hint:
          'Install Chromium/Chrome (apt install chromium) or set CHROME_PATH to the ' +
          'browser executable. Without it, performance + rendered-a11y checks do NOT ' +
          'run and the score is capped until they can.',
      };
  return _probe;
}

/**
 * Classify a degraded block into a single concise cause identifier for storage & UI badges.
 * @param {null|{degraded?:boolean,capabilities?:string[]}} degraded
 * @returns {'waf'|'render'|'partial'|null}
 */
function degradedKind(degraded) {
  if (!degraded || !degraded.degraded) return null;
  const caps = Array.isArray(degraded.capabilities) ? degraded.capabilities : [];
  if (caps.includes('waf-intercepted') || caps.includes('waf-bypass') || caps.includes(HEADERS_UNVERIFIED_CAPABILITY)) return 'waf';
  if (caps.includes(RENDER_CAPABILITY)) return 'render';
  return 'partial';
}

/**
 * Build the `degraded` block for a report from whatever the scan learned.
 *
 * @param {string[]} capabilities  capabilities that were expected but unavailable
 * @param {string}   reason        short human explanation
 * @returns {null|{degraded:true, kind:'waf'|'render'|'partial', capabilities:string[], reason:string, hint:string|null, scoreCap:number, unrunChecks:string[]}}
 */
function buildDegraded(capabilities, reason) {
  const caps = [...new Set((capabilities || []).filter(Boolean))];
  if (!caps.length) return null;

  const unrunChecks = [];
  if (caps.includes(RENDER_CAPABILITY)) {
    unrunChecks.push('performance (Core Web Vitals — lab)', 'accessibility (rendered DOM pass)');
  }
  if (caps.includes('waf-bypass') || caps.includes('waf-intercepted')) {
    unrunChecks.push('content heuristics', 'SEO tags', 'cookie compliance', 'accessibility');
  }
  if (caps.includes(HEADERS_UNVERIFIED_CAPABILITY)) {
    unrunChecks.push('HTTP security headers (HSTS, CSP, X-Frame-Options, COOP/CORP)', 'cookie security flags', 'CORS headers');
  }

  const probe = caps.includes(RENDER_CAPABILITY) ? probeRenderCapability() : null;
  const kind = degradedKind({ degraded: true, capabilities: caps });
  const wafBlockedBody = caps.includes('waf-bypass') || caps.includes('waf-intercepted');

  return {
    degraded: true,
    kind,
    capabilities: caps,
    reason: reason || 'a required scan capability was unavailable',
    hint: probe ? probe.hint : 'Origin requires interactive browser challenge resolution.',
    // The cap is a *ceiling*: full WAF block caps at 70; missing headers/renderer cap at 79.
    scoreCap: wafBlockedBody ? 70 : DEGRADED_SCORE_CAP,
    unrunChecks,
  };
}

/**
 * Attach the degrade block to a finished report and apply the score cap.
 * Idempotent. Returns the report (mutated in place) for convenience.
 */
function applyDegraded(report, degraded) {
  if (!report || !degraded) return report;

  if (degraded.degraded) report.degraded = degraded;

  // Cap the headline score. Keep the pre-cap value so the UI can explain it.
  if (degraded.degraded && typeof report.score === 'number' && report.score > degraded.scoreCap) {
    report.scoreUncapped = report.score;
    report.score = degraded.scoreCap;
    report.grade = gradeFor(degraded.scoreCap);
    report.scoreCeiling = Math.min(
      typeof report.scoreCeiling === 'number' ? report.scoreCeiling : 100,
      degraded.scoreCap
    );
  }

  // Also cap unrun or partial domains (0 findings because checks were suspended,
  // or domains skipped under WAF challenge / headless-render / unverified-headers
  // even when peripheral checks like /robots.txt emitted info findings) so the UI
  // never displays 100/100 unverified next to a degraded overall score.
  if (degraded.degraded && report.domains && typeof report.domains === 'object') {
    const caps = Array.isArray(degraded.capabilities) ? degraded.capabilities : [];
    const unverifiedDomains = new Set();
    if (caps.includes('waf-intercepted') || caps.includes('waf-bypass')) {
      unverifiedDomains.add('compliance');
      unverifiedDomains.add('performance');
      unverifiedDomains.add('accessibility');
      unverifiedDomains.add('seo');
    }
    if (caps.includes(RENDER_CAPABILITY)) {
      unverifiedDomains.add('performance');
      unverifiedDomains.add('accessibility');
    }
    if (caps.includes(HEADERS_UNVERIFIED_CAPABILITY)) {
      unverifiedDomains.add('security');
    }
    for (const [domKey, domData] of Object.entries(report.domains)) {
      if (!domData || typeof domData.score !== 'number') continue;
      const isUnverified = unverifiedDomains.size > 0
        ? unverifiedDomains.has(domKey)
        : domData.total === 0;
      if (isUnverified) {
        if (domData.score > degraded.scoreCap) {
          domData.score = degraded.scoreCap;
          domData.grade = gradeFor(degraded.scoreCap);
        }
        domData.unverified = true;
      }
    }
  }

  return report;
}

/**
 * Append a visible finding so a degraded run can never be mistaken for a clean
 * one — the finding shows up in the count, in exports, and in SARIF.
 */
function degradedFinding(degraded) {
  if (!degraded || !degraded.degraded) return null;
  const missing = degraded.unrunChecks && degraded.unrunChecks.length
    ? degraded.unrunChecks.join(', ')
    : degraded.capabilities.join(', ');
  return {
    id: 'scan-degraded',
    domain: 'quality',
    severity: 'medium',
    title: 'Scan incomplete — some checks could not run',
    detail:
      `Capability unavailable: ${degraded.capabilities.join(', ')}. ` +
      `Checks that did NOT run: ${missing}. ` +
      'Until they run, the score is capped and cannot be trusted as "verified".',
    fix: degraded.hint || 'Install the required tooling and re-scan.',
    evidence: degraded.reason || null,
  };
}

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D'; // keep in lockstep with scanner.gradeFor()
  return 'F';
}

module.exports = {
  RENDER_CAPABILITY,
  HEADERS_UNVERIFIED_CAPABILITY,
  DEGRADED_SCORE_CAP,
  probeRenderCapability,
  degradedKind,
  buildDegraded,
  applyDegraded,
  degradedFinding,
  gradeFor,
};
