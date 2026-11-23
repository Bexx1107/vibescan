'use strict';
/**
 * Technology fingerprinting and known-vulnerable server / client runtime checks.
 */

const { makeFinding } = require('./findings');

function stripFormControls(chunk) {
  if (!chunk || typeof chunk !== 'string') return '';
  return chunk
    .replace(/<select\b[^>]*>[\s\S]*?<\/select>/gi, ' ')
    .replace(/<option\b[^>]*>[\s\S]*?<\/option>/gi, ' ')
    .replace(/<option\b[^>]*>/gi, ' ');
}

/**
 * Extract resource/metadata tags (<script>, <link>, <img>, <source>, <meta>, <form>)
 * so platform/hosting markers are matched against actual loaded assets or meta generators
 * rather than arbitrary body prose, table cells, or outbound `<a>` / `?q=` links.
 */
function extractAssetMarkup(html) {
  if (!html || typeof html !== 'string') return '';
  const tags = html.match(/<(?:script|link|img|source|meta|form)\b[^>]*>/gi);
  return tags ? tags.join('\n') : '';
}

// Client-side DOM / body signatures (scanned strictly against sanitized body, NOT headers)
const CLIENT_TECH_SIGNATURES = [
  ['Shopify', /cdn\.shopify\.com|shopify\.theme/i],
  ['Wix', /wix\.com|wixstatic/i],
  ['Squarespace', /squarespace\.com|static\.squarespace/i],
  ['Next.js', /__NEXT_DATA__|_next\/static/i],
  ['Nuxt', /__NUXT__|_nuxt\//i],
  ['React', /data-reactroot|react(?:-dom)?[.@]/i],
  ['Vue', /data-v-[0-9a-f]{8}|vue(?:\.runtime)?[.@]/i],
  ['Angular', /ng-version|angular(?:\.min)?\.js/i],
  ['Svelte', /svelte-[0-9a-z]{6}/i],
  ['jQuery', /jquery(?:-[\d.]+)?(?:\.min)?\.js/i],
  ['Bootstrap', /bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)/i],
  ['Tailwind', /tailwind(?:\.min)?\.css|class\s*=\s*"[^"]*\b(?:flex|grid|text-(?:xs|sm|lg|xl)|bg-\w+|p[xy]?-\d)/i],
  ['Google Fonts', /<link[^>]+href=["'][^"']*fonts\.googleapis\.com/i],
  ['Google Fonts', /@import\s+(?:url\()?["']?[^"')]*fonts\.googleapis\.com/i],
  ['Google Fonts', /<link[^>]+href=["'][^"']*fonts\.gstatic\.com/i],
];
const TECH_SIGNATURES = CLIENT_TECH_SIGNATURES;

function detectTech(res, body) {
  const cleanBody = stripFormControls(body || '');
  const assetMarkup = extractAssetMarkup(cleanBody);
  const hits = [];

  // WordPress matched strictly on generator meta tag or actual resource URLs in asset tags
  if (
    /<meta\b[^>]+name\s*=\s*["']generator["'][^>]+wordpress/i.test(assetMarkup) ||
    /<meta\b[^>]+wordpress[^>]+name\s*=\s*["']generator["']/i.test(assetMarkup) ||
    /(?:src|href)\s*=\s*["'](?:https?:\/\/[^/"'?]+)?\/wp-(?:content|includes|json)(?:\/|["'?])/i.test(assetMarkup)
  ) {
    hits.push('WordPress');
  }

  // 1. Client assets and DOM patterns (scanned strictly against sanitized body)
  for (const [name, re] of CLIENT_TECH_SIGNATURES) {
    if (re.test(cleanBody)) hits.push(name);
  }

  // 2. Server & infrastructure indicators (scanned strictly from headers and infra asset markers)
  const headers = (res && res.headers) || {};
  const server = headers.server || '';
  const xPoweredBy = headers['x-powered-by'] || '';

  // Cloudflare
  if (headers['cf-ray'] || headers['cf-cache-status'] || /cloudflare/i.test(server)) {
    hits.push('Cloudflare');
  }

  // Vercel: header indicators or actual Vercel asset URLs (never outbound <a> links, ?q= params, or prose)
  if (
    headers['x-vercel-id'] ||
    headers['x-vercel-cache'] ||
    /vercel/i.test(server) ||
    /(?:src|href)\s*=\s*["'](?:https?:\/\/[^/"'?]+)?\/_vercel\//i.test(assetMarkup) ||
    /(?:src|href)\s*=\s*["']https?:\/\/[a-z0-9-]+\.vercel\.app(?:[/"'?]|$)/i.test(assetMarkup)
  ) {
    hits.push('Vercel');
  }

  // Netlify: header indicators or form/asset deployment markers
  if (
    headers['x-nf-request-id'] ||
    /netlify/i.test(server) ||
    /<form\b[^>]+data-netlify\s*=\s*["']?true/i.test(assetMarkup) ||
    /(?:src|href)\s*=\s*["']https?:\/\/[a-z0-9-]+\.netlify\.app(?:[/"'?]|$)/i.test(assetMarkup)
  ) {
    hits.push('Netlify');
  }

  // Next.js: via X-Powered-By if present
  if (/next\.?js/i.test(xPoweredBy)) {
    hits.push('Next.js');
  }

  // Server banner
  if (server) {
    hits.push('Server: ' + server);
  }

  return [...new Set(hits)];
}

function checkTech(res, body, findings, meta) {
  const tech = detectTech(res, body);
  meta.tech = tech;

  const headers = res.headers || {};
  const serverHeader = (headers.server || headers['x-powered-by'] || '');
  const allHeadersStr = JSON.stringify(headers);

  // 1. General Server Version Disclosures
  if (/\/[0-9]+\.[0-9]+/.test(serverHeader)) {
    findings.push(makeFinding({
      id: 'server-version-leak', domain: 'security', severity: 'low',
      title: 'Server version disclosed in HTTP headers',
      detail: `Header discloses exact version: "${serverHeader}". Attackers use exact version strings to target unpatched CVEs.`,
      fix: 'Configure your web server to suppress detailed version banners (e.g. server_tokens off in nginx).',
      evidence: serverHeader,
    }));
  }

  // 2. PHP Runtime Vulnerabilities (including 2024-2026 EOL and RCE CVEs)
  const phpMatch = serverHeader.match(/PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i) || allHeadersStr.match(/PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (phpMatch) {
    const major = parseInt(phpMatch[1], 10);
    const minor = parseInt(phpMatch[2], 10);
    const ver = phpMatch[0];
    if (major < 8 || (major === 8 && minor === 0)) {
      findings.push(makeFinding({
        id: 'vuln-php-eol', domain: 'security', severity: 'high',
        title: `End-of-Life PHP runtime (${ver}) with known critical CVEs`,
        detail: `The server discloses ${ver}. PHP versions prior to 8.2 are completely end-of-life and susceptible to critical vulnerabilities such as CVE-2024-4577 (Windows CGI argument injection RCE), CVE-2024-8926, and CVE-2024-9026.`,
        fix: 'Upgrade immediately to an actively supported PHP branch (PHP 8.2 or 8.3+) and set expose_php = Off in php.ini.',
        evidence: ver,
      }));
    } else if (major === 8 && minor === 1) {
      findings.push(makeFinding({
        id: 'vuln-php-81-eol', domain: 'security', severity: 'medium',
        title: `End-of-Life PHP 8.1 runtime (${ver})`,
        detail: `PHP 8.1 reached official End-of-Life in November 2024 and no longer receives upstream security updates.`,
        fix: 'Upgrade to PHP 8.2+ or 8.3+ and set expose_php = Off in php.ini.',
        evidence: ver,
      }));
    }
  }

  // 3. Apache HTTP Server Outdated (< 2.4.60)
  const apacheMatch = serverHeader.match(/Apache\/2\.4\.(\d+)/i) || allHeadersStr.match(/Apache\/2\.4\.(\d+)/i);
  if (apacheMatch) {
    const patch = parseInt(apacheMatch[1], 10);
    if (patch < 60) {
      const ver = apacheMatch[0];
      findings.push(makeFinding({
        id: 'vuln-apache-outdated', domain: 'security', severity: 'medium',
        title: `Vulnerable Apache HTTP Server version (${ver})`,
        detail: `Apache ${ver} is affected by multiple security vulnerabilities (including CVE-2024-38472 SSRF, CVE-2024-38475 architecture-level bypass, and CVE-2024-39573 proxy escape).`,
        fix: 'Upgrade Apache to 2.4.62+ and set ServerTokens Prod in your server configuration.',
        evidence: ver,
      }));
    }
  }

  // 4. Node.js Outdated (< 20.x)
  const nodeMatch = serverHeader.match(/Node(?:\.js)?\/?\s*v?(\d+)\.(\d+)/i) || allHeadersStr.match(/Node(?:\.js)?\/?\s*v?(\d+)\.(\d+)/i);
  if (nodeMatch) {
    const major = parseInt(nodeMatch[1], 10);
    if (major < 20) {
      const ver = nodeMatch[0];
      findings.push(makeFinding({
        id: 'vuln-nodejs-eol', domain: 'security', severity: 'medium',
        title: `End-of-Life Node.js runtime (${ver})`,
        detail: `Node.js releases prior to v20 are End-of-Life and miss security fixes (including October 2026 HTTP request smuggling and permission model flaws).`,
        fix: 'Upgrade to active LTS (Node.js 20 or 22) and suppress framework headers via app.disable("x-powered-by").',
        evidence: ver,
      }));
    }
  }

  // 5. Nginx Outdated (< 1.26.1)
  const nginxMatch = serverHeader.match(/nginx\/1\.(\d+)\.(\d+)/i) || allHeadersStr.match(/nginx\/1\.(\d+)\.(\d+)/i);
  if (nginxMatch) {
    const minor = parseInt(nginxMatch[1], 10);
    const patch = parseInt(nginxMatch[2], 10);
    if (minor < 26 || (minor === 26 && patch < 1) || (minor === 27 && patch < 1)) {
      const ver = nginxMatch[0];
      findings.push(makeFinding({
        id: 'vuln-nginx-outdated', domain: 'security', severity: 'low',
        title: `Outdated Nginx version (${ver})`,
        detail: `Nginx ${ver} lacks recent worker reliability and HTTP/2/3 patches (e.g. CVE-2024-34161).`,
        fix: 'Upgrade Nginx to the latest stable release (1.26.2+ / 1.28+) and ensure server_tokens off; is set.',
        evidence: ver,
      }));
    }
  }

  // 6. Known Vulnerable Client Libraries from HTML scripts
  const cleanBody = body || '';
  const jqMatch = cleanBody.match(/jquery[.-](1\.[0-9]+(?:\.[0-9]+)?|2\.[0-9]+(?:\.[0-9]+)?|3\.[0-4](?:\.[0-9]+)?)(?:\.min)?\.js/i);
  if (jqMatch) {
    findings.push(makeFinding({
      id: 'vuln-jquery-outdated', domain: 'security', severity: 'medium',
      title: `Vulnerable jQuery version (${jqMatch[1]})`,
      detail: `The page loads jQuery ${jqMatch[1]}. Versions prior to 3.5.0 contain known Cross-Site Scripting (XSS) vulnerabilities in htmlPrefilter (CVE-2020-11022, CVE-2020-11023).`,
      fix: 'Upgrade jQuery to version 3.7.1+ or migrate to native DOM APIs.',
      evidence: jqMatch[0],
    }));
  }

  if (/angular(?:\.min)?\.js|ng-version=["']1\./i.test(cleanBody)) {
    findings.push(makeFinding({
      id: 'vuln-angularjs-eol', domain: 'security', severity: 'medium',
      title: 'End-of-Life AngularJS 1.x detected',
      detail: 'AngularJS 1.x reached official End-of-Life on December 31, 2021. It has numerous known client-side template injection and sandbox escape XSS vulnerabilities.',
      fix: 'Migrate legacy AngularJS components to modern supported frameworks (React, Vue, Svelte, or modern Angular).',
      evidence: 'AngularJS 1.x script or ng-version marker detected in DOM',
    }));
  }

  // 7. Malicious Supply Chain: Polyfill.io / BootCDN / BootCSS (CVE-2024-38521)
  const polyfillMatch = cleanBody.match(/(?:https?:)?\/\/(?:[a-zA-Z0-9-]+\.)?(?:polyfill\.io|bootcdn\.net|bootcss\.com)[^\s"'>]*/i);
  if (polyfillMatch) {
    findings.push(makeFinding({
      id: 'vuln-polyfill-malicious', domain: 'security', severity: 'critical',
      title: 'Malicious supply chain dependency (Polyfill.io / BootCDN)',
      detail: `The page loads scripts from a known compromised domain (${polyfillMatch[0]}). The polyfill.io service was acquired by a rogue entity in 2024 and observed distributing malware and unauthorized redirects to mobile visitors (CVE-2024-38521).`,
      fix: 'Remove references to polyfill.io immediately. Migrate to Cloudflare\'s secure mirror (cdnjs.cloudflare.com/polyfill) or modern standard ECMAScript APIs.',
      evidence: polyfillMatch[0],
    }));
  }

  // 8. WordPress Core Outdated (< 6.6.2)
  const wpMatch = cleanBody.match(/<meta\s+name=["']generator["']\s+content=["']WordPress\s+(\d+)\.(\d+)(?:\.(\d+))?["']/i) ||
                  cleanBody.match(/wp-embed\.min\.js\?ver=(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (wpMatch) {
    const wpMajor = parseInt(wpMatch[1], 10);
    const wpMinor = parseInt(wpMatch[2], 10);
    const wpPatch = wpMatch[3] ? parseInt(wpMatch[3], 10) : 0;
    const isOld = (wpMajor < 6) || (wpMajor === 6 && wpMinor < 6) || (wpMajor === 6 && wpMinor === 6 && wpPatch < 2);
    if (isOld) {
      const wpVer = `${wpMajor}.${wpMinor}${wpMatch[3] ? '.' + wpPatch : ''}`;
      findings.push(makeFinding({
        id: 'vuln-wordpress-outdated', domain: 'security', severity: wpMajor < 6 || (wpMajor === 6 && wpMinor < 5) ? 'high' : 'medium',
        title: `Outdated WordPress core (${wpVer})`,
        detail: `WordPress ${wpVer} is affected by multiple known security vulnerabilities, including CVE-2024-4439 (SSRF/code execution in avatar blocks) and CVE-2024-31210 (privilege escalation).`,
        fix: 'Upgrade WordPress core to the latest stable release (6.7+) immediately and enable automatic security updates.',
        evidence: wpMatch[0],
      }));
    }
  }

  // 9. Next.js Server Actions SSRF / Cache Poisoning (< 14.1.1)
  const nextDataMatch = cleanBody.match(/<script\s+id=["']__NEXT_DATA__["'][^>]*>(.*?)<\/script>/s);
  let nextVer = null;
  if (nextDataMatch) {
    try {
      const parsed = JSON.parse(nextDataMatch[1]);
      if (parsed && parsed.version) nextVer = String(parsed.version);
    } catch (_) {}
  }
  if (!nextVer && headers['x-nextjs-version']) {
    nextVer = String(headers['x-nextjs-version']);
  }
  if (nextVer) {
    const nextVm = nextVer.match(/^(\d+)\.(\d+)\.(\d+)/);
    if (nextVm) {
      const nMaj = parseInt(nextVm[1], 10);
      const nMin = parseInt(nextVm[2], 10);
      const nPat = parseInt(nextVm[3], 10);
      if (nMaj < 14 || (nMaj === 14 && (nMin === 0 || (nMin === 1 && nPat < 1)))) {
        findings.push(makeFinding({
          id: 'vuln-nextjs-ssrf', domain: 'security', severity: 'high',
          title: `Vulnerable Next.js version (${nextVer}) with Server Actions SSRF`,
          detail: `Next.js ${nextVer} is vulnerable to CVE-2024-34351 (Server-Side Request Forgery via Server Actions Host header manipulation) and cache poisoning flaws.`,
          fix: 'Upgrade Next.js to 14.2.15+ or 15.0+ to ensure Server Actions request origin validation is enforced.',
          evidence: `Next.js ${nextVer}`,
        }));
      }
    }
  }

  // 10. Lodash Outdated Prototype Pollution (< 4.17.21)
  const lodashMatch = cleanBody.match(/lodash[.-]([0-3]\.[0-9]+(?:\.[0-9]+)?|4\.(?:[0-9]|1[0-6])(?:\.[0-9]+)?|4\.17\.(?:[0-9]|1[0-9]|20))(?:\.min)?\.js/i);
  if (lodashMatch) {
    findings.push(makeFinding({
      id: 'vuln-lodash-outdated', domain: 'security', severity: 'medium',
      title: `Vulnerable Lodash version (${lodashMatch[1]})`,
      detail: `The page loads Lodash ${lodashMatch[1]}. Versions prior to 4.17.21 contain known Prototype Pollution vulnerabilities (CVE-2020-8203) and command injection in template compilation (CVE-2021-23337).`,
      fix: 'Upgrade Lodash to version 4.17.21+ or migrate to native JavaScript ES2022+ utility methods.',
      evidence: lodashMatch[0],
    }));
  }

  // 11. Bootstrap Outdated XSS (< 4.3.1 / 3.x)
  const bsMatch = cleanBody.match(/bootstrap[.-]([0-3]\.[0-9]+(?:\.[0-9]+)?|4\.[0-2](?:\.[0-9]+)?)(?:\.bundle)?(?:\.min)?\.(?:js|css)/i);
  if (bsMatch) {
    findings.push(makeFinding({
      id: 'vuln-bootstrap-outdated', domain: 'security', severity: 'medium',
      title: `Vulnerable Bootstrap library version (${bsMatch[1]})`,
      detail: `Bootstrap ${bsMatch[1]} contains known Cross-Site Scripting (XSS) vulnerabilities in tooltip, popover, and scrollspy data-attributes (CVE-2019-8331, CVE-2018-14041).`,
      fix: 'Upgrade Bootstrap to version 5.3+ or update to the patched 4.6.2 release.',
      evidence: bsMatch[0],
    }));
  }

  // 12. Moment.js Outdated ReDoS (< 2.29.4)
  const momentMatch = cleanBody.match(/moment[.-]([0-1]\.[0-9]+(?:\.[0-9]+)?|2\.(?:[0-9]|1[0-9]|2[0-8])(?:\.[0-9]+)?)(?:\.min)?\.js/i);
  if (momentMatch) {
    findings.push(makeFinding({
      id: 'vuln-moment-redos', domain: 'security', severity: 'low',
      title: `Outdated Moment.js library (${momentMatch[1]})`,
      detail: `Moment.js ${momentMatch[1]} is susceptible to Regular Expression Denial of Service (ReDoS) and path traversal in locale handling (CVE-2022-31129, CVE-2022-24785).`,
      fix: 'Upgrade Moment.js to 2.30.1+ or replace with lightweight alternatives like Day.js or native Intl APIs.',
      evidence: momentMatch[0],
    }));
  }

  // 13. Axios Outdated Client Library (< 1.7.4)
  const axiosMatch = cleanBody.match(/axios[.-](0\.[0-9]+(?:\.[0-9]+)?|1\.[0-6](?:\.[0-9]+)?|1\.7\.[0-3])(?:\.min)?\.js/i);
  if (axiosMatch) {
    findings.push(makeFinding({
      id: 'vuln-axios-outdated', domain: 'security', severity: 'medium',
      title: `Outdated Axios library (${axiosMatch[1]})`,
      detail: `Axios ${axiosMatch[1]} contains known SSRF bypass vulnerabilities (CVE-2024-39338) and cross-origin credential disclosure during redirects (CVE-2023-45857).`,
      fix: 'Upgrade Axios to version 1.7.7+ or use the native fetch API.',
      evidence: axiosMatch[0],
    }));
  }
}

module.exports = {
  stripFormControls,
  CLIENT_TECH_SIGNATURES,
  TECH_SIGNATURES,
  detectTech,
  checkTech,
};
