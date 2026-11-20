'use strict';
/**
 * VibeScan Penetration Testing Engine — Nuclei DAST Bridge
 * Executes active DAST templates, CVE exploits, misconfigurations, and fuzzing
 * against the target URL using ProjectDiscovery Nuclei (14,000+ templates).
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const LOCAL_NUCLEI = path.join(os.homedir(), '.local', 'bin', 'nuclei');
const NUCLEI_BIN = fs.existsSync(LOCAL_NUCLEI)
  ? LOCAL_NUCLEI
  : 'nuclei';

/**
 * Runs Nuclei against targetUrl.
 * @param {string} targetUrl
 * @param {object} options
 */
function runNucleiScan(targetUrl, options = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const findings = [];

    // Tags to execute: CVEs, DAST active injections, exposures, misconfigurations, takeovers
    const tags = options.tags || 'cve,dast,vuln,exposure,misconfig,takeover';
    const severity = options.severity || 'critical,high,medium,low';
    const rateLimit = String(options.rateLimit || 30);
    const maxTime = options.maxTime || '2m';

    const args = [
      '-u', targetUrl,
      '-tags', tags,
      '-s', severity,
      '-rate-limit', rateLimit,
      '-timeout', '6',
      '-max-time', maxTime,
      '-jsonl',
      '-silent',
      '-no-color',
    ];

    console.log(`[nuclei] running: ${NUCLEI_BIN} ${args.join(' ')}`);

    let proc;
    try {
      proc = spawn(NUCLEI_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      console.error('[nuclei] spawn failed:', err.message);
      return resolve({ findings: [], durationMs: Date.now() - started, error: err.message });
    }

    let buffer = '';

    proc.stdout.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep remainder

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('{')) continue;
        try {
          const item = JSON.parse(trimmed);
          if (item && item.info) {
            const info = item.info;
            const sev = (info.severity || 'medium').toLowerCase();
            const tmplId = item['template-id'] || path.basename(item.template || 'tmpl', '.yaml');
            const matchedAt = item['matched-at'] || targetUrl;
            const curlCmd = item['curl-command'] || '';
            const ref = Array.isArray(info.reference) ? info.reference[0] : (info.reference || '');

            findings.push({
              id: `nuclei-${tmplId}`,
              domain: 'security',
              severity: ['critical', 'high', 'medium', 'low', 'info'].includes(sev) ? sev : 'medium',
              title: `[Pentest] ${info.name || tmplId}`,
              detail: info.description || `Nuclei active exploit template ${tmplId} matched on ${matchedAt}.`,
              fix: info.remediation || (ref ? `Inspect advisory and patch: ${ref}` : 'Remediate the vulnerable endpoint or apply network access restrictions.'),
              evidence: `Matched: ${matchedAt}\n${curlCmd ? `PoC curl:\n${curlCmd}` : ''}`.trim(),
              whatItIs: info.description || info.name,
              whoCanAct: 'An unauthenticated attacker able to reach this web endpoint.',
              impact: `Active penetration test finding discovered by Nuclei engine (${tmplId}).`,
              worstCase: 'Data breach, credential leakage, remote takeover, or injection execution.',
              exploitSteps: curlCmd ? ['Execute PoC curl command:', curlCmd] : [`Target matched endpoint: ${matchedAt}`],
              meta: {
                nuclei: true,
                template: tmplId,
                tags: info.tags || [],
                cve: info.classification && info.classification['cve-id'],
                matchedAt,
              },
            });
          }
        } catch (_) {}
      }
    });

    let stderr = '';
    proc.stderr.on('data', (c) => { stderr += c.toString('utf8'); });

    proc.on('close', (code) => {
      if (buffer.trim().startsWith('{')) {
        try {
          const item = JSON.parse(buffer.trim());
          if (item && item.info) {
            const info = item.info;
            const sev = (info.severity || 'medium').toLowerCase();
            const tmplId = item['template-id'] || 'tmpl';
            findings.push({
              id: `nuclei-${tmplId}`,
              domain: 'security',
              severity: ['critical', 'high', 'medium', 'low', 'info'].includes(sev) ? sev : 'medium',
              title: `[Pentest] ${info.name || tmplId}`,
              detail: info.description || info.name,
              fix: info.remediation || 'Remediate the vulnerable endpoint.',
              evidence: `Matched: ${item['matched-at'] || targetUrl}`,
            });
          }
        } catch (_) {}
      }

      console.log(`[nuclei] finished in ${Date.now() - started}ms with code ${code}, found ${findings.length} findings`);
      resolve({
        findings,
        durationMs: Date.now() - started,
        error: code !== 0 && findings.length === 0 ? stderr.slice(0, 300) : null,
      });
    });

    proc.on('error', (err) => {
      resolve({ findings: [], durationMs: Date.now() - started, error: err.message });
    });
  });
}

module.exports = {
  runNucleiScan,
  NUCLEI_BIN,
  isAvailable: () => fs.existsSync(NUCLEI_BIN),
};
