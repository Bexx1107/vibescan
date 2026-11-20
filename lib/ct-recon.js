/**
 * Certificate Transparency (CT) Reconnaissance Engine
 * Queries public CT logs (crt.name / agniops) to discover apex domain subdomains,
 * detecting development, staging, and administrative exposure.
 */

const dns = require('dns');

const STAGING_RE = /(?:^|\.)(?:dev|staging|stage|test|qa|beta|sandbox|preview|newdev)(?:$|\.)/i;
const ADMIN_RE = /(?:^|\.)(?:admin|portal|cpanel|whm|internal)(?:$|\.)/i;

async function resolveSubdomainDns(host, timeoutMs = 1500) {
  try {
    const ips = await Promise.race([
      dns.promises.resolve4(host),
      new Promise((_, reject) => setTimeout(() => reject(new Error('TIMEOUT')), timeoutMs)),
    ]);
    if (Array.isArray(ips) && ips.length > 0) {
      return { host, live: true, status: 'LIVE', ip: ips[0], ips };
    }
  } catch (err) {
    const isNx = err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA');
    return {
      host,
      live: false,
      status: isNx ? 'NXDOMAIN' : 'HISTORICAL',
      error: err && err.code ? err.code : String(err && err.message ? err.message : err),
    };
  }
  return { host, live: false, status: 'HISTORICAL' };
}

function sanitizeApex(domain) {
  if (!domain || typeof domain !== 'string') return '';
  let clean = domain.trim().toLowerCase();
  clean = clean.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  clean = clean.split('/')[0];
  clean = clean.split('?')[0];
  clean = clean.split('#')[0];
  clean = clean.split(':')[0];
  clean = clean.replace(/^www\./i, '');
  return clean;
}

async function fetchSubdomains(apexDomain) {
  const cleanApex = sanitizeApex(apexDomain);
  if (!cleanApex || !cleanApex.includes('.') || /^\d+\.\d+\.\d+\.\d+$/.test(cleanApex)) {
    return { total: 0, subdomains: [], staging: [], stagingLive: [], stagingHistorical: [], admin: [], dns: [] };
  }

  let bodyText = '';
  try {
    const res = await fetch(`https://crt.name/v1/search?apex=${encodeURIComponent(cleanApex)}`, {
      signal: AbortSignal.timeout(4000),
      headers: { 'User-Agent': 'VibeScan/2.0' },
    });
    if (res.ok) {
      bodyText = await res.text();
    } else {
      throw new Error(`crt.name HTTP ${res.status}`);
    }
  } catch (e1) {
    try {
      const res2 = await fetch(`https://app.agniops.in/v1/search?domain=${encodeURIComponent(cleanApex)}`, {
        signal: AbortSignal.timeout(4000),
        headers: { 'User-Agent': 'VibeScan/2.0' },
      });
      if (res2.ok) {
        bodyText = await res2.text();
      }
    } catch (e2) {
      // Both queries failed/timed out
    }
  }

  let rawList = [];
  if (bodyText) {
    const trimmed = bodyText.trim();
    if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          for (const item of parsed) {
            if (typeof item === 'string') rawList.push(item);
            else if (item && typeof item === 'object') {
              const val = item.subdomain || item.name || item.domain || Object.values(item)[0];
              if (typeof val === 'string') rawList.push(val);
            }
          }
        } else if (parsed && typeof parsed === 'object') {
          const arr = parsed.subdomains || parsed.domains || parsed.results || parsed.data || [];
          if (Array.isArray(arr)) {
            for (const item of arr) {
              if (typeof item === 'string') rawList.push(item);
              else if (item && typeof item === 'object') {
                const val = item.subdomain || item.name || item.domain || Object.values(item)[0];
                if (typeof val === 'string') rawList.push(val);
              }
            }
          }
        }
      } catch {
        // Fall back to newline split
      }
    }
    if (rawList.length === 0 && trimmed) {
      rawList = trimmed.split(/[\r\n]+/);
    }
  }

  const seen = new Set();
  const subdomains = [];
  const apexSuffix = '.' + cleanApex;
  for (const item of rawList) {
    if (typeof item !== 'string') continue;
    let s = item.trim().toLowerCase();
    s = s.replace(/^\*\./, '');
    s = s.replace(/\.$/, '');
    if (!s) continue;
    if (s === cleanApex || s.endsWith(apexSuffix)) {
      if (!seen.has(s)) {
        seen.add(s);
        subdomains.push(s);
      }
    }
  }

  const staging = subdomains.filter((s) => STAGING_RE.test(s));
  const admin = subdomains.filter((s) => ADMIN_RE.test(s));

  // Perform quick DNS resolution check on staging subdomains + detected subdomains
  const toCheck = new Set([...staging, ...admin, ...subdomains.slice(0, 35)]);
  const dnsChecks = await Promise.all([...toCheck].map((s) => resolveSubdomainDns(s, 1500)));
  const dnsMap = new Map();
  for (const check of dnsChecks) {
    dnsMap.set(check.host, check);
  }

  const dnsResults = subdomains.map((s) => {
    return dnsMap.get(s) || { host: s, live: false, status: 'UNCHECKED' };
  });

  const stagingLive = staging.filter((s) => dnsMap.get(s)?.live);
  const stagingHistorical = staging.filter((s) => !dnsMap.get(s)?.live);

  return {
    total: subdomains.length,
    subdomains,
    staging,
    stagingLive,
    stagingHistorical,
    admin,
    dns: dnsResults,
  };
}

async function checkSubdomains(apexDomain, findings, meta, mkProbe) {
  try {
    const result = await fetchSubdomains(apexDomain);
    meta.ct = {
      count: result.total,
      subdomains: result.subdomains,
      all: result.dns || result.subdomains.map((s) => ({ host: s })),
      sample: result.subdomains.slice(0, 10),
      staging: result.staging,
      stagingLive: result.stagingLive || [],
      stagingHistorical: result.stagingHistorical || [],
      admin: result.admin,
      dns: result.dns || [],
    };

    if (result.staging && result.staging.length > 0) {
      const liveCount = result.stagingLive ? result.stagingLive.length : 0;
      const histCount = result.stagingHistorical ? result.stagingHistorical.length : 0;
      const hasLive = liveCount > 0;

      const evidenceLines = [
        `Certificate Transparency reconnaissance discovered ${result.total} subdomain(s):`,
      ];
      if (result.dns && result.dns.length > 0) {
        for (const item of result.dns) {
          const isStaging = result.staging.includes(item.host);
          const tag = isStaging ? ' [STAGING]' : '';
          const statusStr = item.live
            ? `LIVE (${item.ip || 'A record'})`
            : `${item.status || 'NXDOMAIN'} (inactive DNS)`;
          evidenceLines.push(`• ${item.host} → ${statusStr}${tag}`);
        }
      } else {
        for (const s of result.subdomains) {
          const isStaging = result.staging.includes(s);
          evidenceLines.push(`• ${s}${isStaging ? ' [STAGING]' : ''}`);
        }
      }
      const evidenceText = evidenceLines.slice(0, 35).join('\n') +
        (result.total > 35 ? `\n... and ${result.total - 35} more subdomains` : '');

      const title = hasLive
        ? `Development / staging subdomains indexed in Certificate Transparency logs (${liveCount} active)`
        : `Historical staging subdomain(s) in Certificate Transparency logs (${histCount} inactive/NXDOMAIN)`;

      const desc = hasLive
        ? `Public Certificate Transparency logs expose ${result.staging.length} staging/dev subdomain(s), with ${liveCount} currently active in DNS: ${result.stagingLive.slice(0, 5).join(', ')}. Attackers inspect CT logs to locate unhardened staging environments or exposed debug tools.`
        : `Public Certificate Transparency logs record ${result.staging.length} historical staging/dev subdomain(s): ${result.staging.slice(0, 5).join(', ')}. These hostnames currently resolve to NXDOMAIN (inactive DNS), but historic logs reveal organizational development naming conventions.`;

      const f = mkProbe(
        'ct-exposed-staging',
        hasLive ? 'low' : 'info',
        title,
        desc,
        'Ensure development and staging environments are restricted behind private VPN, IP whitelisting, or Cloudflare Zero Trust (Access) rather than public DNS/HTTP.',
        evidenceText
      );
      f.whatItIs = 'Public Certificate Transparency logs contain issued SSL certificates for test or development environments.';
      f.impact = hasLive
        ? 'Exposes unhardened code, debug endpoints, or legacy software to reconnaissance.'
        : 'Reveals development infrastructure history and naming patterns to passive OSINT collectors.';
      f.worstCase = hasLive
        ? 'Attacker accesses staging database or exploits development credentials to breach production.'
        : 'Attacker monitors expiring domain or creates lookalike development assets.';
      findings.push(f);
    }

    return result;
  } catch (err) {
    if (!meta.ct) {
      meta.ct = { count: 0, sample: [], subdomains: [], all: [], staging: [], stagingLive: [], stagingHistorical: [], admin: [], error: err.message };
    }
  }
}

module.exports = {
  fetchSubdomains,
  checkSubdomains,
  sanitizeApex,
  resolveSubdomainDns,
  STAGING_RE,
  ADMIN_RE,
};
