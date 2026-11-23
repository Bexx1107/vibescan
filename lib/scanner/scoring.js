'use strict';
/**
 * Scoring v2 math, per-domain aggregation, per-page check runner, and crawl merge.
 */

const { SEVERITY_WEIGHT } = require('./findings');
const {
  checkTransport,
  checkSecurityHeaders,
  checkModernHeaders,
  checkCookies,
  checkCors,
} = require('./headers');
const { checkBody } = require('./content');
const { checkTech } = require('./tech');

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

/** Penalty → 0–100 score for an arbitrary subset of findings. */
function penaltyToScore(list) {
  const penalty = list.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

/**
 * Overall score (Scoring v2).
 *
 * The old model was a flat penalty sum across *all* findings clamped at 0.
 * That made the headline number meaningless: a site could score A/B in five of
 * six domains and still show "0 — grade F", because ~30 low/info hygiene notes
 * plus two medium issues already exceed 100 penalty. It also contradicted the
 * per-domain scorecard sitting directly above it.
 *
 * Now the overall score is the mean of the per-domain scores (so the domains
 * with no findings pull it up, exactly as the scorecard implies), then a
 * severity ceiling is applied so a genuine critical/high issue can never be
 * hidden behind a good average:
 *   - any critical           → cap at 69 (C)
 *   - 2+ high                → cap at 74 (C)
 *   - exactly 1 high         → cap at 84 (B)
 * The raw flat penalty is still reported as `penalty` for callers that want it.
 */
function scoreCeiling(findings) {
  const n = (sev) => findings.filter((f) => f.severity === sev).length;
  if (n('critical') > 0) return 69;
  if (n('high') >= 4) return 74;
  if (n('high') >= 2) return 82;
  if (n('high') === 1) return 88;
  return 100;
}

function scoreFindings(findings) {
  const domains = scoreByDomain(findings);
  const keys = Object.keys(domains);
  const mean = keys.length
    ? Math.round(keys.reduce((s, k) => s + domains[k].score, 0) / keys.length)
    : 100;
  const ceiling = scoreCeiling(findings);
  const score = Math.max(0, Math.min(100, Math.min(mean, ceiling)));
  return { score, grade: gradeFor(score), penalty: penaltyFlat(findings), domainScore: mean };
}

/** Raw flat penalty (severity sum) — kept for transparency / exports. */
function penaltyFlat(findings) {
  return findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
}

/**
 * Per-domain breakdown (Scoring v2). The overall score stays the flat
 * penalty model (so nothing regresses); each domain is scored on its own
 * findings only, which lets the UI show *where* the problems live instead of
 * a single opaque number.
 */
const SCORE_DOMAINS = ['security', 'compliance', 'performance', 'accessibility', 'seo', 'quality'];

function scoreByDomain(findings) {
  const out = {};
  for (const d of SCORE_DOMAINS) {
    const list = findings.filter((f) => f.domain === d);
    const p = list.reduce((s, f) => s + (SEVERITY_WEIGHT[f.severity] || 0), 0);
    const score = penaltyToScore(list);
    out[d] = {
      score,
      grade: gradeFor(score),
      counts: list.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {}),
      total: list.length,
      penalty: p,
    };
  }
  return out;
}

// Per-page sweep shared by the root page and every crawled page.
function runPageChecks(res) {
  const f = [];
  const m = {};
  checkTransport(res, f, m);
  checkSecurityHeaders(res, f, m);
  checkModernHeaders(res, f, m);
  checkCookies(res, f, m);
  checkBody(res.body, res, f, m);
  checkCors(res, f, m);
  checkTech(res, res.body, f, m);
  return { findings: f, meta: m };
}

/**
 * De-duplicate per-page findings across a crawl. Identical issue IDs collapse
 * into one finding; the list of affected URLs is attached as evidence so the
 * report stays readable instead of repeating "3 images without alt" N times.
 */
function mergePageFindings(rootFindings, pageResults) {
  const byId = new Map();
  for (const f of rootFindings) byId.set(f.id, { finding: f, pages: [] });

  for (const pr of pageResults) {
    for (const f of pr.findings) {
      const entry = byId.get(f.id);
      if (entry) {
        entry.pages.push(pr.url);
      } else {
        byId.set(f.id, { finding: f, pages: [pr.url] });
      }
    }
  }

  const merged = [];
  for (const { finding, pages } of byId.values()) {
    if (pages.length) {
      const uniq = [...new Set(pages)].slice(0, 12);
      finding.evidence = (finding.evidence ? finding.evidence + '\n' : '') +
        `Also found on ${uniq.length} page(s):\n` + uniq.join('\n');
    }
    merged.push(finding);
  }
  return merged;
}

module.exports = {
  gradeFor,
  penaltyToScore,
  scoreCeiling,
  scoreFindings,
  penaltyFlat,
  SCORE_DOMAINS,
  scoreByDomain,
  runPageChecks,
  mergePageFindings,
};
