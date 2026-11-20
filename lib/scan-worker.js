'use strict';
/**
 * Isolated scan worker process for VibeScan.
 *
 * Spawned by lib/queue.js via child_process.fork() in its own detached
 * process group so heavy HTML/DOM/regex analysis or hung Chromium subprocesses
 * never block the main HTTP server event loop and can be reaped cleanly via
 * process-group SIGKILL on timeout.
 */

const { scan } = require('./scanner');

let exiting = false;
let started = false;

function safeSend(payload) {
  if (!process.connected || typeof process.send !== 'function') return;
  try {
    process.send(payload);
  } catch (_) {}
}

/**
 * Flush the final IPC result/error message cleanly before exiting so the parent
 * process always receives the payload before the IPC channel closes.
 */
function sendAndExit(payload, code) {
  if (exiting) return;
  exiting = true;

  if (!process.connected || typeof process.send !== 'function') {
    process.exit(code);
    return;
  }

  const fallback = setTimeout(() => {
    process.exit(code);
  }, 3000);

  try {
    process.send(payload, undefined, undefined, () => {
      clearTimeout(fallback);
      process.exit(code);
    });
  } catch (_) {
    clearTimeout(fallback);
    process.exit(code);
  }
}

process.on('uncaughtException', (err) => {
  const message = err && err.message ? err.message : String(err);
  sendAndExit({ type: 'error', message }, 1);
});

process.on('unhandledRejection', (reason) => {
  const message = reason && reason.message ? reason.message : String(reason);
  sendAndExit({ type: 'error', message }, 1);
});

process.on('disconnect', () => {
  if (!exiting) process.exit(1);
});

process.on('message', async (msg) => {
  if (!msg || msg.type !== 'run' || started) return;
  started = true;

  const url = msg.url;
  const options = msg.options && typeof msg.options === 'object' ? msg.options : {};

  try {
    const scanOpts = Object.assign({}, options, {
      onProgress: (phase, meta = {}) => {
        safeSend({ type: 'progress', phase, meta });
      },
    });

    const report = await scan(url, scanOpts);

    if (options.pentest || options.profile === 'pentest') {
      try {
        const nuclei = require('./nuclei');
        const nRes = await nuclei.runNucleiScan(report.finalUrl || url, {
          severity: options.nucleiSeverity || 'critical,high,medium,low',
          tags: options.nucleiTags,
          maxTime: '2m',
        });
        if (nRes && nRes.findings && nRes.findings.length) {
          report.findings.push(...nRes.findings);
          report.counts = {
            critical: report.findings.filter((f) => f.severity === 'critical').length,
            high: report.findings.filter((f) => f.severity === 'high').length,
            medium: report.findings.filter((f) => f.severity === 'medium').length,
            low: report.findings.filter((f) => f.severity === 'low').length,
            info: report.findings.filter((f) => f.severity === 'info').length,
          };
          const penalty = report.counts.critical * 30 + report.counts.high * 15 + report.counts.medium * 5;
          report.score = Math.max(0, Math.min(100, report.score - penalty));
          report.grade = report.score >= 90 ? 'A' : report.score >= 80 ? 'B' : report.score >= 70 ? 'C' : report.score >= 55 ? 'D' : 'F';
        }
        if (nRes) {
          report.durationMs = (report.durationMs || 0) + (nRes.durationMs || 0);
          report.meta = report.meta || {};
          report.meta.nuclei = {
            enabled: true,
            durationMs: nRes.durationMs,
            findingsCount: nRes.findings ? nRes.findings.length : 0,
          };
        }
      } catch (_) {}
    }

    sendAndExit({ type: 'result', report }, 0);
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    sendAndExit({ type: 'error', message }, 1);
  }
});
