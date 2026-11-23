'use strict';
/**
 * Shared secret-leak patterns and WAF / bot-challenge detection heuristics.
 */

const SECRET_PATTERNS = [
  ['AWS access key', /AKIA[0-9A-Z]{16}/g],
  ['Stripe secret key', /sk_live_[0-9a-zA-Z]{24,}/g],
  ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ['Slack token', /xox[baprs]-[0-9A-Za-z-]{10,}/g],
  ['Generic bearer/JWT', /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}/g],
  ['Supabase service role', /service_role["'\s:]+eyJ[A-Za-z0-9_-]{10,}/g],
  ['GitHub Personal Access Token', /(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}/g],
  ['SendGrid API key', /SG\.[0-9a-zA-Z_\-\.]{66}/g],
];

function scanSecrets(text) {
  const found = [];
  for (const [label, re] of SECRET_PATTERNS) {
    re.lastIndex = 0;
    const matches = text.match(re) || [];
    const validMatches = matches.filter((m) => {
      if (label === 'Generic bearer/JWT') {
        try {
          const parts = m.split('.');
          if (parts.length >= 2) {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
            // Ignore public vendor telemetry tokens (e.g. Netlify CWV/RUM telemetry beacon token)
            if (payload && payload.iss === 'netlify') return false;
            // Ignore public Supabase anon client tokens (operates under PostgreSQL RLS)
            if (payload && payload.iss === 'supabase' && payload.role === 'anon') return false;
          }
        } catch (_) {}
      }
      return true;
    });
    if (validMatches.length) found.push(`${label} (${validMatches.length} match${validMatches.length > 1 ? 'es' : ''})`);
  }
  return found;
}

function detectWaf(res, body) {
  if (!res && !body) return { isWaf: false, provider: null };
  const status = (res && (res.status || res.statusCode)) || 0;
  const headers = (res && res.headers) || {};
  const server = String(headers['server'] || '').toLowerCase();
  const cdn = String(headers['x-cdn'] || '').toLowerCase();
  const cfMitigated = String(headers['cf-mitigated'] || '').toLowerCase();
  const serverTiming = String(headers['server-timing'] || '').toLowerCase();
  const xIinfo = String(headers['x-iinfo'] || '');
  const xDataDome = String(headers['x-datadome'] || '');
  const xAmznWaf = String(headers['x-amzn-waf-action'] || '');
  const via = String(headers['via'] || '').toLowerCase();

  const rawCookies = headers['set-cookie'] || [];
  const cookieStr = (Array.isArray(rawCookies) ? rawCookies.join('; ') : String(rawCookies)).toLowerCase();
  const b = typeof body === 'string' ? body : (body ? String(body) : '');

  // If request successfully bypassed WAF via Firecrawl (or another verified bypass),
  // do not treat the authentic page as an active WAF challenge/block unless it is actually an interstitial page.
  if (res && (res.via === 'firecrawl' || res.bypassedWaf) && status === 200) {
    const isCfTitle = /<title>(?:Just a moment\.\.\.|Attention Required! \| Cloudflare)<\/title>/i.test(b);
    if (isCfTitle || (b.length < 25000 && /__cf_chl_opt/i.test(b) && !/<(?:main|article|nav|header|footer)/i.test(b))) {
      return { isWaf: true, provider: 'Cloudflare' };
    }
    return { isWaf: false, provider: null };
  }

  // 1. Imperva / Incapsula
  const isImpervaHeader = cdn.includes('imperva') || cdn.includes('incapsula') || Boolean(xIinfo);
  const isImpervaCookie = /visid_incap|incap_ses|nlbi_/.test(cookieStr);
  const isImpervaBody = /_incapsula_resource|distil_referrer|incapsula incident id|request forbidden by administrative rules/i.test(b);
  if (isImpervaHeader || isImpervaCookie || isImpervaBody) {
    if (status === 403 || status === 429 || status === 503 || isImpervaBody || (status === 200 && b.length < 3000 && /incap/i.test(b))) {
      return { isWaf: true, provider: 'Imperva' };
    }
  }

  // 2. Cloudflare Bot Management / Challenge
  const isCfHeader = cfMitigated === 'challenge' || serverTiming.includes('chlray') || ((status === 403 || status === 429) && server.includes('cloudflare'));
  const isCfTitle = /<title>(?:Just a moment\.\.\.|Attention Required! \| Cloudflare)<\/title>/i.test(b);
  const isCfInterstitial = isCfTitle ||
    ((status === 403 || status === 429 || status === 503) && /cf-turnstile|challenges\.cloudflare\.com|challenge-platform|__cf_chl_/i.test(b)) ||
    (b.length < 25000 && /__cf_chl_opt/i.test(b) && !/<(?:main|article|nav|header|footer)/i.test(b));
  if (isCfHeader || isCfInterstitial) {
    return { isWaf: true, provider: 'Cloudflare' };
  }

  // 3. DataDome
  const isDataDomeHeader = Boolean(xDataDome) || server.includes('datadome');
  const isDataDomeCookie = cookieStr.includes('datadome');
  const isDataDomeBlock = /geo\.captcha-delivery\.com/i.test(b) || ((status === 403 || status === 429) && (/datadome/i.test(b) || isDataDomeHeader || isDataDomeCookie));
  if (isDataDomeBlock) {
    return { isWaf: true, provider: 'DataDome' };
  }

  // 4. Akamai
  const isAkamaiHeader = server.includes('akamai') || server.includes('ghost') || Boolean(headers['x-akamai-transformed']);
  const isAkamaiBody = /Reference\s*#[0-9a-f.]+|AkamaiGHost|You don't have permission to access/i.test(b);
  if (isAkamaiHeader || isAkamaiBody) {
    if (status === 403 || status === 429 || (isAkamaiBody && /access denied/i.test(b))) {
      return { isWaf: true, provider: 'Akamai' };
    }
  }

  // 5. AWS WAF / CloudFront
  const isAwsWafHeader = Boolean(xAmznWaf);
  const isAwsWafCookie = cookieStr.includes('awswaf');
  const isCloudFrontError = (status === 403 || status === 429) && (via.includes('cloudfront') || /Generated by cloudfront|The request could not be satisfied/i.test(b));
  if (isAwsWafHeader || isAwsWafCookie || isCloudFrontError || /awswaf/i.test(b)) {
    return { isWaf: true, provider: 'AWS WAF' };
  }

  // 6. Vercel Bot Mitigation / Security Checkpoint
  const xVercelMitigated = String(headers['x-vercel-mitigated'] || '').toLowerCase();
  const isVercelHeader = xVercelMitigated === 'challenge' || ((status === 403 || status === 429) && (Boolean(headers['x-vercel-challenge-token']) || server.includes('vercel')));
  const isVercelBody = /<title>Vercel Security Checkpoint<\/title>|Vercel Security Checkpoint/i.test(b);
  if ((status === 403 || status === 429) && (isVercelHeader || isVercelBody)) {
    return { isWaf: true, provider: 'Vercel' };
  }
  if (isVercelBody && b.length < 50000) {
    return { isWaf: true, provider: 'Vercel' };
  }

  // 7. Hostinger CDN / hcdn Bot Challenge
  const isHostinger = server.includes('hcdn') || String(headers['platform'] || '').toLowerCase().includes('hostinger');
  const isHostingerChallenge = /Checking your browser before accessing/i.test(b) ||
    /\/hcdn-cgi\/jschallenge/i.test(b) ||
    /Please wait for up to 5 seconds/i.test(b);
  if (isHostingerChallenge || (isHostinger && (status === 403 || status === 429))) {
    return { isWaf: true, provider: 'Hostinger' };
  }

  // 8. Generic WAF / Bot challenge
  if (status === 403 || status === 429) {
    if (b.length < 4096 && /access denied|request forbidden|bot detection|unusual traffic|firewall|rate limit|security challenge|please verify you are human|turnstile|captcha|security block|blocked by administrative/i.test(b)) {
      return { isWaf: true, provider: server.includes('cloudflare') ? 'Cloudflare' : 'Generic WAF' };
    }
    if (b.length < 2048) {
      return { isWaf: true, provider: server.includes('cloudflare') ? 'Cloudflare' : 'Generic WAF' };
    }
  }

  // 9. Explicit block / HTTP error body (e.g. from headless DOM or unparsed status)
  const isExplicitBlock = b.length < 10000 && (
    /<title>[^<]*(?:403\s+Forbidden|401\s+Unauthorized|429\s+Too\s+Many|503\s+Service|Access\s+Denied|Request\s+Forbidden)[^<]*<\/title>/i.test(b) ||
    /<h[12]>[^<]*(?:403\s+Forbidden|Access\s+Denied|Request\s+forbidden|Administrative\s+rules)[^<]*<\/h[12]>/i.test(b) ||
    (/openresty/i.test(b) && /403\s+Forbidden/i.test(b)) ||
    (/cloudflare/i.test(b) && /error\s+10\d\d/i.test(b))
  );
  if (isExplicitBlock) {
    return { isWaf: true, provider: server.includes('cloudflare') || /cloudflare/i.test(b) ? 'Cloudflare' : 'Server WAF/Block' };
  }

  return { isWaf: false, provider: null };
}

function isWafChallenge(res, body) {
  return detectWaf(res, body).isWaf;
}

module.exports = {
  SECRET_PATTERNS,
  scanSecrets,
  detectWaf,
  isWafChallenge,
};
