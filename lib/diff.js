'use strict';
/**
 * VibeScan report diffing (Phase 1).
 *
 * Compares two scan reports for the same target and answers the two questions
 * that actually matter between runs:
 *   1. What is NEW since last time?  (regressions)
 *   2. What got FIXED / disappeared? (progress)
 *
 * A finding is identified by its `id` plus a normalised slice of its evidence,
 * so two different instances of the same check (e.g. two pages missing CSP)
 * stay separate entries.
 */

function evidenceKey(f) {
  const ev = f && f.evidence;
  let s;
  if (ev == null) s = '';
  else if (typeof ev === 'string') s = ev;
  else {
    try { s = JSON.stringify(ev); } catch { s = String(ev); }
  }
  return s.replace(/\s+/g, ' ').trim().slice(0, 160);
}

function sig(f) {
  return (f && f.id ? f.id : 'unknown') + '|' + evidenceKey(f);
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function bySeverity(a, b) {
  return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
}

/** Sum of severity weights — used for a coarse "did it get worse?" number. */
function riskScore(findings) {
  const w = { critical: 40, high: 15, medium: 6, low: 2, info: 0 };
  return (findings || []).reduce((n, f) => n + (w[f.severity] || 0), 0);
}

function diffReports(previous, latest) {
  const prevList = (previous && previous.findings) || [];
  const nextList = (latest && latest.findings) || [];

  const prevMap = new Map();
  for (const f of prevList) { const k = sig(f); if (!prevMap.has(k)) prevMap.set(k, f); }
  const nextMap = new Map();
  for (const f of nextList) { const k = sig(f); if (!nextMap.has(k)) nextMap.set(k, f); }

  const added = [];
  const removed = [];
  const persisted = [];
  const severityChanged = [];

  for (const [k, f] of nextMap) {
    const before = prevMap.get(k);
    if (!before) added.push(f);
    else {
      persisted.push(f);
      if (before.severity !== f.severity) {
        severityChanged.push({
          id: f.id,
          title: f.title,
          from: before.severity,
          to: f.severity,
          direction: (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[before.severity] ?? 9) ? 'worse' : 'better',
        });
      }
    }
  }
  for (const [k, f] of prevMap) if (!nextMap.has(k)) removed.push(f);

  added.sort(bySeverity);
  removed.sort(bySeverity);
  severityChanged.sort((a, b) => (SEV_ORDER[a.to] ?? 9) - (SEV_ORDER[b.to] ?? 9));

  const scorePrev = previous && typeof previous.score === 'number' ? previous.score : null;
  const scoreNow = latest && typeof latest.score === 'number' ? latest.score : null;
  const scoreDelta = (scorePrev != null && scoreNow != null) ? scoreNow - scorePrev : null;

  const riskPrev = riskScore(prevList);
  const riskNow = riskScore(nextList);

  return {
    target: (latest && latest.target) || (previous && previous.target) || null,
    hasPrevious: !!previous,
    previous: previous ? { id: previous.startedAt, at: previous.startedAt, score: previous.score, grade: previous.grade } : null,
    latest: latest ? { id: latest.startedAt, at: latest.startedAt, score: latest.score, grade: latest.grade } : null,
    score: { previous: scorePrev, latest: scoreNow, delta: scoreDelta },
    grade: {
      previous: previous ? previous.grade : null,
      latest: latest ? latest.grade : null,
      changed: !!previous && previous.grade !== (latest && latest.grade),
    },
    risk: { previous: riskPrev, latest: riskNow, delta: riskNow - riskPrev },
    counts: {
      previous: (previous && previous.counts) || {},
      latest: (latest && latest.counts) || {},
      previousTotal: prevList.length,
      latestTotal: nextList.length,
    },
    added,
    removed,
    persistedCount: persisted.length,
    severityChanged,
    summary: previous
      ? `${added.length} new, ${removed.length} fixed, ${severityChanged.length} changed severity` +
        (scoreDelta != null ? `, score ${scoreDelta >= 0 ? '+' : ''}${scoreDelta}` : '')
      : `first scan — ${nextList.length} findings, score ${scoreNow}`,
  };
}

module.exports = { diffReports, sig, riskScore };
