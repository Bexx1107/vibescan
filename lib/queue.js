'use strict';
/**
 * VibeScan process-isolated job queue.
 *
 * Scans execute inside forked child worker processes (lib/scan-worker.js)
 * running in detached process groups so:
 *   1. Heavy CPU/regex/DOM work never blocks the HTTP server event loop.
 *   2. Up to CONCURRENCY (default 2) scans run concurrently on multi-core hosts.
 *   3. Hung targets or runaway Chromium subprocesses are hard-killed as a
 *      process group at JOB_TIMEOUT_MS (default 120s).
 *   4. Deep reports stay strictly in ephemeral RAM (never persisted to disk),
 *      while SQLite writes (db.recordScan) happen solely in this parent process.
 */

const path = require('path');
const { fork } = require('child_process');

const CONCURRENCY = Math.max(1, Math.min(4, parseInt(process.env.VIBESCAN_CONCURRENCY || '2', 10) || 2));
const JOB_TIMEOUT_MS = Math.max(15000, parseInt(process.env.VIBESCAN_JOB_TIMEOUT_MS || '120000', 10) || 120000);
const MAX_QUEUED = Math.max(5, parseInt(process.env.VIBESCAN_MAX_QUEUED || '25', 10) || 25);

let workerScript = process.env.VIBESCAN_WORKER_SCRIPT || path.join(__dirname, 'scan-worker.js');

const jobs = new Map();
const ephemeralReports = new Map();
const EPHEMERAL_TTL_MS = 10 * 60 * 1000; // 10 minutes in RAM only; NEVER written to disk

const queue = [];
const activeWorkers = new Map(); // jobId -> { child, timer, graceTimer, job }
let seq = 0;

function _setWorkerScript(nextPath) {
  workerScript = nextPath || path.join(__dirname, 'scan-worker.js');
}

function pruneEphemeral() {
  const now = Date.now();
  for (const [id, entry] of ephemeralReports.entries()) {
    if (now - entry.createdAt > EPHEMERAL_TTL_MS) {
      ephemeralReports.delete(id);
    }
  }
  if (jobs.size > 100) {
    const sorted = [...jobs.values()].sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1));
    while (jobs.size > 60 && sorted.length) {
      const oldest = sorted.shift();
      if (oldest.status === 'done' || oldest.status === 'error') {
        jobs.delete(oldest.id);
      }
    }
  }
}

function getEphemeralReport(reportId) {
  pruneEphemeral();
  const hit = ephemeralReports.get(reportId);
  return hit ? hit.report : null;
}

function killWorkerGroup(child) {
  if (!child) return;
  if (Number.isInteger(child.pid) && child.pid > 1) {
    try {
      process.kill(-child.pid, 'SIGKILL');
      return;
    } catch (_) {}
  }
  try {
    child.kill('SIGKILL');
  } catch (_) {}
}

function normalizeDedupUrl(rawUrl) {
  const s = String(rawUrl || '').trim();
  try {
    const u = new URL(s);
    u.hash = '';
    const host = u.hostname.toLowerCase();
    const port = u.port ? ':' + u.port : '';
    const pathname = u.pathname === '/' ? '/' : u.pathname.replace(/\/+$/, '') || '/';
    return `${u.protocol.toLowerCase()}//${host}${port}${pathname}${u.search}`;
  } catch (_) {
    return s.toLowerCase();
  }
}

function dedupKey(url, options = {}) {
  return JSON.stringify([
    normalizeDedupUrl(url),
    Boolean(options.hideResults),
    options.followRedirects !== false,
    options.profile || 'default',
    Boolean(options.pentest || options.profile === 'pentest'),
    Boolean(options.skipActive),
    options.deep !== false,
  ]);
}

function sanitizeWorkerOptions(options = {}) {
  try {
    return JSON.parse(JSON.stringify(options || {}));
  } catch (_) {
    const clean = {};
    for (const [k, v] of Object.entries(options || {})) {
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' || v === null) {
        clean[k] = v;
      }
    }
    return clean;
  }
}

function snapshot(job) {
  const queueIdx = job.status === 'queued' ? queue.findIndex((j) => j.id === job.id) : -1;
  return {
    id: job.id,
    url: job.url,
    status: job.status,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    reportMeta: job.reportMeta || null,
    diff: null,
    error: job.error || null,
    progress: job.progress || null,
    queued: queue.map((j) => j.id),
    queuePosition: queueIdx >= 0 ? queueIdx + 1 : 0,
    hideResults: Boolean(job.options && job.options.hideResults),
  };
}

function storeCompletedReport(job, report) {
  // ZERO-PERSISTENCE POLICY FOR DEEP LOW-LEVEL SCANS:
  // Never write full reports to disk (`data/reports/*.json` or `history.json`).
  // Hold the deep report ephemerally in RAM only for the active browser session.
  pruneEphemeral();
  const ephemeralId = 'ephem-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7);
  ephemeralReports.set(ephemeralId, { report, createdAt: Date.now() });
  job.reportMeta = {
    id: ephemeralId,
    target: report.target,
    finalUrl: report.finalUrl,
    score: report.score,
    grade: report.grade,
    at: report.startedAt,
  };

  // Mirror ONLY general 1-100 numbers into the public leaderboard DB
  // (unless the user checked "Hide Results").
  if (!job.options || !job.options.hideResults) {
    try {
      require('./db').recordScan(report, {
        reportId: '',
        deep: !job.options || job.options.deep !== false,
      });
    } catch (err) {
      console.error('[leaderboard] recordScan failed:', err.message);
    }
  }
}

function runJobInWorker(job) {
  job.status = 'running';
  job.startedAt = new Date().toISOString();
  job.progress = { phase: 'dns', phaseIdx: 0, msg: 'Preverjam DNS zapise in TLS certifikat …' };

  const workerOptions = sanitizeWorkerOptions(job.options);
  const timeoutMs =
    Number.isFinite(workerOptions.timeoutMs) && workerOptions.timeoutMs >= 100
      ? Math.min(workerOptions.timeoutMs, 300000)
      : JOB_TIMEOUT_MS;

  let child;
  try {
    child = fork(workerScript, [], {
      detached: true,
      execArgv: ['--max-old-space-size=512'],
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
  } catch (err) {
    job.status = 'error';
    job.error = err && err.message ? err.message : String(err);
    job.progress = { phase: 'error', error: job.error };
    job.finishedAt = new Date().toISOString();
    setImmediate(drain);
    return;
  }

  let settled = false;
  let exited = false;
  let stderrTail = '';

  const entry = { child, timer: null, graceTimer: null, job };
  activeWorkers.set(job.id, entry);

  if (child.stdout) {
    child.stdout.on('data', () => {});
  }
  if (child.stderr) {
    child.stderr.on('data', (chunk) => {
      stderrTail = (stderrTail + chunk.toString('utf8')).slice(-2048);
    });
  }

  const cleanupEntry = (forceKillGroup) => {
    if (entry.timer) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
    if (forceKillGroup) {
      if (entry.graceTimer) {
        clearTimeout(entry.graceTimer);
        entry.graceTimer = null;
      }
      killWorkerGroup(child);
    } else if (!exited && !entry.graceTimer) {
      entry.graceTimer = setTimeout(() => {
        entry.graceTimer = null;
        if (!exited) killWorkerGroup(child);
      }, 1500);
      entry.graceTimer.unref();
    }
    activeWorkers.delete(job.id);
    setImmediate(drain);
  };

  const finalizeSuccess = (report) => {
    if (settled) return;
    settled = true;
    try {
      storeCompletedReport(job, report);
      job.status = 'done';
      job.progress = { phase: 'done', phaseIdx: 3, msg: 'Zaključeno' };
    } catch (err) {
      job.status = 'error';
      job.error = err && err.message ? err.message : String(err);
      job.progress = { phase: 'error', error: job.error };
    }
    job.finishedAt = new Date().toISOString();
    cleanupEntry(false);
  };

  const finalizeError = (message, forceKillGroup) => {
    if (settled) return;
    settled = true;
    job.status = 'error';
    job.error = message || 'Scan failed';
    job.progress = { phase: 'error', error: job.error };
    job.finishedAt = new Date().toISOString();
    cleanupEntry(forceKillGroup);
  };

  entry.timer = setTimeout(() => {
    console.error(`[queue] job ${job.id} (${job.url}) timed out after ${timeoutMs}ms; killing worker pid=${child.pid}`);
    finalizeError('Scan timed out (target took too long to respond or render)', true);
  }, timeoutMs);

  child.on('message', (msg) => {
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'progress') {
      if (!settled) {
        job.progress = Object.assign({ phase: msg.phase }, msg.meta || {});
      }
      return;
    }
    if (msg.type === 'result') {
      finalizeSuccess(msg.report);
      return;
    }
    if (msg.type === 'error') {
      finalizeError(msg.message || 'Scan failed', false);
    }
  });

  child.on('error', (err) => {
    finalizeError(err && err.message ? err.message : String(err), true);
  });

  child.on('exit', (code, signal) => {
    exited = true;
    if (entry.graceTimer) {
      clearTimeout(entry.graceTimer);
      entry.graceTimer = null;
    }
    if (!settled) {
      if (stderrTail.trim()) {
        console.error(`[queue] worker ${job.id} stderr: ${stderrTail.trim()}`);
      }
      const msg = signal
        ? `Scan worker terminated (${signal})`
        : `Scan worker exited unexpectedly (code ${code})`;
      finalizeError(msg, true);
    }
  });

  try {
    child.send({ type: 'run', url: job.url, options: workerOptions });
  } catch (err) {
    finalizeError(err && err.message ? err.message : String(err), true);
  }
}

function drain() {
  while (activeWorkers.size < CONCURRENCY && queue.length > 0) {
    const job = queue.shift();
    runJobInWorker(job);
  }
}

function findMatchingInFlight(key) {
  for (const j of jobs.values()) {
    if (j.dedupKey === key && (j.status === 'queued' || j.status === 'running')) {
      return j;
    }
  }
  return null;
}

function isFull(url, options = {}) {
  if (url && !options.noDedup) {
    const key = dedupKey(url, options);
    if (findMatchingInFlight(key)) return false;
  }
  return queue.length >= MAX_QUEUED;
}

function enqueue(url, options = {}) {
  const key = dedupKey(url, options);
  if (!options.noDedup) {
    const existing = findMatchingInFlight(key);
    if (existing) {
      return snapshot(existing);
    }
  }

  if (queue.length >= MAX_QUEUED) {
    const err = new Error('Scanner queue is currently full. Please try again in a minute.');
    err.code = 'QUEUE_FULL';
    throw err;
  }

  seq += 1;
  const job = {
    id: 'job-' + Date.now().toString(36) + '-' + seq,
    url,
    options,
    dedupKey: key,
    status: 'queued',
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    reportMeta: null,
    diff: null,
    error: null,
    progress: { phase: 'queued' },
  };
  jobs.set(job.id, job);
  queue.push(job);
  setImmediate(drain);
  return snapshot(job);
}

function get(id) {
  const job = jobs.get(id);
  return job ? snapshot(job) : null;
}

function list(limit = 25) {
  return [...jobs.values()]
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
    .slice(0, limit)
    .map(snapshot);
}

/** { queued, running, done, error, total, concurrency, maxQueued, activeWorkers } counts for /api/health. */
function stats() {
  const out = {
    queued: 0,
    running: 0,
    done: 0,
    error: 0,
    total: jobs.size,
    concurrency: CONCURRENCY,
    maxQueued: MAX_QUEUED,
    activeWorkers: activeWorkers.size,
  };
  for (const j of jobs.values()) out[j.status] = (out[j.status] || 0) + 1;
  return out;
}

function shutdown() {
  while (queue.length) {
    const j = queue.shift();
    j.status = 'error';
    j.error = 'Server restarting';
    j.progress = { phase: 'error', error: j.error };
    j.finishedAt = new Date().toISOString();
  }
  for (const entry of [...activeWorkers.values()]) {
    if (entry.timer) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
    if (entry.graceTimer) {
      clearTimeout(entry.graceTimer);
      entry.graceTimer = null;
    }
    entry.job.status = 'error';
    entry.job.error = 'Server restarting';
    entry.job.progress = { phase: 'error', error: entry.job.error };
    entry.job.finishedAt = new Date().toISOString();
    killWorkerGroup(entry.child);
  }
  activeWorkers.clear();
}

module.exports = {
  enqueue,
  get,
  list,
  stats,
  jobs,
  getEphemeralReport,
  isFull,
  shutdown,
  CONCURRENCY,
  MAX_QUEUED,
  JOB_TIMEOUT_MS,
  _setWorkerScript,
};
