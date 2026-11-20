'use strict';
/**
 * VibeScan Local Project Source Security Auditor (White-box)
 * Scans local repositories (e.g. ~/my-project) directly from disk.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const probes = require('./probes');

const IGNORE_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'archive', 'coverage']);
const CODE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json']);

function walk(dir, fileList = [], maxFiles = 1000, ignoreDirs = IGNORE_DIRS) {
  if (fileList.length >= maxFiles) return fileList;
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_) { return fileList; }

  for (const entry of entries) {
    if (fileList.length >= maxFiles) break;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!ignoreDirs.has(entry.name)) {
        walk(fullPath, fileList, maxFiles, ignoreDirs);
      }
    } else if (entry.isFile()) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

async function runLocalSourceAudit(repoPath) {
  const started = Date.now();
  const repoName = path.basename(repoPath);
  const findings = [];
  let score = 100;

  // 1. .env permissions & gitignore check
  const envFiles = ['.env', '.env.local', '.env.production', '.env.development'];
  let gitignoreContent = '';
  try {
    gitignoreContent = fs.readFileSync(path.join(repoPath, '.gitignore'), 'utf8');
  } catch (_) {}

  for (const envName of envFiles) {
    const envPath = path.join(repoPath, envName);
    if (fs.existsSync(envPath)) {
      const stat = fs.statSync(envPath);
      const isWorldReadable = (stat.mode & 0o044) !== 0;
      if (isWorldReadable) {
        score -= 15;
        findings.push({
          id: `local-env-permissions-${envName}`,
          domain: 'security',
          severity: 'high',
          title: `${envName} is world-readable (${(stat.mode & 0o777).toString(8)})`,
          detail: `Local secrets file has permissive file permissions, allowing other local OS users/processes to read live API keys and credentials.`,
          fix: `Run chmod 600 ${envPath} to restrict read/write access exclusively to the owner.`,
          evidence: `${envName} mode: ${(stat.mode & 0o777).toString(8)}`,
        });
      }

      if (!gitignoreContent.includes(envName) && !gitignoreContent.includes('.env*')) {
        score -= 20;
        findings.push({
          id: `local-env-not-gitignored-${envName}`,
          domain: 'security',
          severity: 'critical',
          title: `${envName} is not listed in .gitignore`,
          detail: `Environment file risks being accidentally committed to version control and pushed to remote git repositories.`,
          fix: `Add ${envName} to ${path.join(repoPath, '.gitignore')}.`,
          evidence: `.gitignore missing rule for ${envName}`,
        });
      }
    }
  }

  // 2. Hardcoded secrets scanning
  const ignoredDirs = new Set(IGNORE_DIRS);
  if (gitignoreContent) {
    const lines = gitignoreContent.split(/\r?\n/);
    for (let l of lines) {
      l = l.trim();
      if (!l || l.startsWith('#')) continue;
      const clean = l.replace(/\/+$/, '').replace(/^\/+/, '');
      if (clean && !clean.includes('*') && !clean.includes('/')) {
        ignoredDirs.add(clean);
      }
    }
  }

  const allFiles = walk(repoPath, [], 1500, ignoredDirs);
  const leakedSecrets = [];

  for (const file of allFiles) {
    const ext = path.extname(file).toLowerCase();
    const basename = path.basename(file);
    // Skip reading actual .env files for repo secret scan (we already checked permissions)
    if (basename.startsWith('.env')) continue;
    if (!CODE_EXTS.has(ext)) continue;

    try {
      const content = fs.readFileSync(file, 'utf8');
      const matches = probes.scanExtendedSecrets(content);
      if (matches.length) {
        const rel = path.relative(repoPath, file);
        for (const m of matches) {
          leakedSecrets.push({ file: rel, name: m.name, sample: m.sample });
        }
      }
    } catch (_) {}
  }

  if (leakedSecrets.length) {
    score -= 25;
    findings.push({
      id: 'local-hardcoded-secrets',
      domain: 'security',
      severity: 'critical',
      title: `${leakedSecrets.length} hardcoded credential(s) detected in source code`,
      detail: `Live API keys, tokens, or credentials were found hardcoded directly in repository source files instead of being loaded via environment variables.`,
      fix: `Remove the hardcoded strings, rotate the exposed credentials immediately, and reference process.env instead.`,
      evidence: leakedSecrets.slice(0, 8).map((s) => `${s.file} → ${s.name}: ${s.sample.slice(0, 35)}…`).join('\n'),
    });
  }

  // 3. API route authorization inspection
  const apiFiles = allFiles.filter((f) => {
    const norm = f.replace(/\\/g, '/');
    return (norm.includes('/app/api/') || norm.includes('/pages/api/') || norm.includes('/routes/')) &&
           (norm.endsWith('.ts') || norm.endsWith('.js') || norm.endsWith('.tsx'));
  });

  const unauthRoutes = [];
  for (const f of apiFiles) {
    try {
      const code = fs.readFileSync(f, 'utf8');
      const rel = path.relative(repoPath, f);
      // Skip intentionally public endpoints (webhooks, telemetry pings, public health/login)
      if (/(?:webhook|telemetry|visit|health|callback|request-link|verify)/i.test(rel)) continue;

      // Check for mutation handlers: POST, PUT, DELETE, PATCH
      const hasMutation = /export\s+(?:async\s+)?function\s+(?:POST|PUT|DELETE|PATCH)\b/i.test(code) ||
                          /app\.(?:post|put|delete|patch)\b/i.test(code) ||
                          /router\.(?:post|put|delete|patch)\b/i.test(code);
      if (hasMutation) {
        const hasAuth = /(?:auth|getSession|verifySession|requireAuth|currentUser|checkAuth|bearer|authorized|headers\.get\(['"]authorization)/i.test(code);
        if (!hasAuth) {
          unauthRoutes.push(rel);
        }
      }
    } catch (_) {}
  }

  if (unauthRoutes.length) {
    score -= 15;
    findings.push({
      id: 'local-unauth-mutations',
      domain: 'security',
      severity: 'high',
      title: `${unauthRoutes.length} state-changing API route(s) appear unauthenticated`,
      detail: `POST/PUT/DELETE handlers in API routes lack evident session/authentication checks, potentially allowing unauthenticated clients to trigger mutations.`,
      fix: `Inspect each route handler and enforce session authentication (e.g. await auth() or requireUser()).`,
      evidence: unauthRoutes.slice(0, 10).join('\n'),
    });
  }

  // 4. npm audit vulnerability extraction
  if (fs.existsSync(path.join(repoPath, 'package.json'))) {
    try {
      const auditOut = execSync('npm audit --json', { cwd: repoPath, timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] }).toString();
      const auditData = JSON.parse(auditOut);
      const vulns = auditData.metadata && auditData.metadata.vulnerabilities;
      if (vulns && (vulns.critical || vulns.high)) {
        score -= (vulns.critical * 10 + vulns.high * 4);
        findings.push({
          id: 'local-npm-cve-vulnerabilities',
          domain: 'security',
          severity: vulns.critical ? 'critical' : 'high',
          title: `Dependencies contain ${vulns.critical || 0} critical and ${vulns.high || 0} high CVE vulnerabilities`,
          detail: `npm packages currently installed have published security advisories.`,
          fix: `Run 'npm audit fix' or update affected dependencies in package.json.`,
          evidence: `Vulnerabilities: Critical=${vulns.critical || 0}, High=${vulns.high || 0}, Moderate=${vulns.moderate || 0}, Low=${vulns.low || 0}`,
        });
      }
    } catch (_) {}
  }

  score = Math.max(20, Math.min(100, score));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 55 ? 'D' : 'F';

  return {
    id: `local-${Date.now()}`,
    target: repoPath,
    finalUrl: `local://${repoName}`,
    startedAt: new Date(started).toISOString(),
    score,
    grade,
    durationMs: Date.now() - started,
    status: 200,
    domains: {
      security: { score, grade, total: findings.length },
      compliance: { score: 100, grade: 'A', total: 0 },
      performance: { score: 100, grade: 'A', total: 0 },
      accessibility: { score: 100, grade: 'A', total: 0 },
      seo: { score: 100, grade: 'A', total: 0 },
      quality: { score: 100, grade: 'A', total: 0 },
    },
    counts: {
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      info: findings.filter((f) => f.severity === 'info').length,
    },
    findings,
    meta: {
      localAudit: true,
      filesScanned: allFiles.length,
      apiRoutesChecked: apiFiles.length,
    },
  };
}

module.exports = { runLocalSourceAudit };
