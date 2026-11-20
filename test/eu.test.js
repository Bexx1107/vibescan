'use strict';

const test = require('node:test');
const assert = require('node:assert');
const eu = require('../lib/eu');
const { checkPolicies } = require('../lib/scanner');

const mk = (id, severity, title, desc, rec, obs) => ({ id, severity, title, desc, rec, obs, detail: desc, fix: rec, evidence: obs });

test('WordPress Divi theme .et-cart-info CSS does not trigger DSA trader info (school site false positive)', () => {
  const schoolHtml = `
    <!DOCTYPE html>
    <html lang="sl">
    <head>
      <title>Osnovna šola</title>
      <style id="divi-style-inline">
        span.et_close_search_field:after,#et-top-navigation .et-cart-info{color:#262626}
        .et-fixed-header #et-top-navigation .et-cart-info{color:#262626!important}
      </style>
    </head>
    <body>
      <header><h1>Osnovna šola Primer</h1></header>
      <main>
        <p>Dobrodošli na spletni strani naše šole. Naročite se na e-novice za obvestila o šolskem koledarju.</p>
      </main>
      <footer>
        <p>Javni zavod Osnovna šola Primer</p>
      </footer>
    </body>
    </html>
  `;
  const meta = {};
  const findings = eu.checkEuCompliance(schoolHtml, { headers: {} }, [], meta, {}, mk);
  const dsa = findings.find((f) => f.id === 'eu-dsa-trader-info');
  assert.strictEqual(dsa, undefined, 'expected no eu-dsa-trader-info on non-commerce school page');
});

test('real e-commerce cart/checkout action triggers DSA trader info when impressum is missing', () => {
  const shopHtml = `
    <!DOCTYPE html>
    <html>
    <head><title>Trgovina</title></head>
    <body>
      <h1>Knjigarna</h1>
      <button class="buy-btn">V košarico</button>
    </body>
    </html>
  `;
  const meta = {};
  const findings = eu.checkEuCompliance(shopHtml, { headers: {} }, [], meta, {}, mk);
  const dsa = findings.find((f) => f.id === 'eu-dsa-trader-info');
  assert.ok(dsa, 'expected eu-dsa-trader-info on genuine e-commerce page missing impressum');
  assert.strictEqual(dsa.severity, 'medium');
});

test('checkPolicies does not flag missing terms or cookie policy on school site with cookie banner', () => {
  const schoolHtml = `
    <!DOCTYPE html>
    <html lang="sl">
    <head><title>Osnovna šola</title></head>
    <body>
      <header><a href="/kontakt">Kontakt</a></header>
      <main>
        <p>Vzgoja in izobraževanje za osnovnošolce.</p>
      </main>
      <div class="acb-banner-content">
        Spletišče uporablja le piškotke, ki so potrebni za delovanje storitve.
        <a href="https://os-primer.example/izjava-o-zasebnosti/">Politika zasebnosti</a>
        <button type="button">Zapri</button>
      </div>
    </body>
    </html>
  `;
  const findings = [];
  const meta = { cookies: ['session'], trackers: [] };
  checkPolicies([schoolHtml], findings, meta);

  const policyTerms = findings.find((f) => f.id === 'policy-terms');
  assert.strictEqual(policyTerms, undefined, 'non-commerce school site should not require terms of service');

  const policyCookie = findings.find((f) => f.id === 'policy-cookie-policy');
  assert.strictEqual(policyCookie, undefined, 'cookie disclosure in banner should satisfy cookie policy requirement');
});

test('checkPolicies requires terms on actual e-commerce store when terms link is absent', () => {
  const shopHtml = `
    <!DOCTYPE html>
    <html>
    <head><title>Spletna trgovina</title></head>
    <body>
      <main>
        <button>V košarico</button>
      </main>
      <footer>
        <a href="/kontakt">Kontakt</a>
        <a href="/zasebnost">Politika zasebnosti</a>
      </footer>
    </body>
    </html>
  `;
  const findings = [];
  const meta = {};
  checkPolicies([shopHtml], findings, meta);

  const policyTerms = findings.find((f) => f.id === 'policy-terms');
  assert.ok(policyTerms, 'commercial shop must provide terms of service');
  assert.strictEqual(policyTerms.severity, 'medium');
});

test('checkEuCompliance detects ungated session replay script (CIPA wiretapping / GDPR risk)', () => {
  const replayHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Test Page</title>
      <script src="https://static.hotjar.com/c/hotjar-123456.js?sv=6"></script>
    </head>
    <body>
      <h1>Welcome</h1>
    </body>
    </html>
  `;
  const meta = {};
  const findings = eu.checkEuCompliance(replayHtml, { headers: {} }, [], meta, {}, mk);
  const replayFinding = findings.find((f) => f.id === 'privacy-session-replay');
  assert.ok(replayFinding, 'expected privacy-session-replay finding');
  assert.strictEqual(replayFinding.severity, 'high');
  assert.match(replayFinding.detail, /CIPA/i);
});

test('checkEuCompliance detects pre-ticked consent checkbox under GDPR Art. 4(11) & Planet49', () => {
  const formHtml = `
    <!DOCTYPE html>
    <html>
    <body>
      <form action="/subscribe">
        <input type="email" name="email" placeholder="Your email">
        <label>
          <input type="checkbox" name="newsletter_consent" checked>
          Naročam se na tedenske e-novice in marketinška obvestila
        </label>
        <button type="submit">Pošlji</button>
      </form>
    </body>
    </html>
  `;
  const meta = {};
  const findings = eu.checkEuCompliance(formHtml, { headers: {} }, [], meta, {}, mk);
  const preticked = findings.find((f) => f.id === 'eu-preticked-consent');
  assert.ok(preticked, 'expected eu-preticked-consent finding');
  assert.strictEqual(preticked.severity, 'medium');
  assert.match(preticked.detail, /Planet49/i);
});

test('checkEuCompliance detects missing US opt-out / GPC mechanism when trackers run', () => {
  const trackerHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123XYZ"></script>
    </head>
    <body>
      <h1>Corporate Site</h1>
      <footer>
        <a href="/about">About Us</a>
      </footer>
    </body>
    </html>
  `;
  const meta = { trackers: ['Google Analytics'] };
  const findings = eu.checkEuCompliance(trackerHtml, { headers: {} }, [], meta, {}, mk);
  const gpcFinding = findings.find((f) => f.id === 'us-gpc-optout');
  assert.ok(gpcFinding, 'expected us-gpc-optout finding');
  assert.strictEqual(gpcFinding.severity, 'medium');
  assert.match(gpcFinding.detail, /CCPA|TDPSA|GPC/i);
});

test('checkEuCompliance passes US opt-out when "Your Privacy Choices" or GPC link is present', () => {
  const trackerHtmlWithGpc = `
    <!DOCTYPE html>
    <html>
    <head>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123XYZ"></script>
    </head>
    <body>
      <h1>Corporate Site</h1>
      <footer>
        <a href="/privacy-choices">Your Privacy Choices</a>
      </footer>
    </body>
    </html>
  `;
  const meta = { trackers: ['Google Analytics'] };
  const findings = eu.checkEuCompliance(trackerHtmlWithGpc, { headers: {} }, [], meta, {}, mk);
  const gpcFinding = findings.find((f) => f.id === 'us-gpc-optout');
  assert.strictEqual(gpcFinding, undefined, 'expected no us-gpc-optout when Your Privacy Choices is present');
});

test('checkA11yStatic detects focus indicator suppression in static stylesheet without replacement', () => {
  const a11y = require('../lib/a11y');
  const badA11yHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <title>Accessible Title</title>
      <style>
        button:focus, a:focus { outline: none; }
      </style>
    </head>
    <body>
      <main>
        <h1>Main Content</h1>
        <button>Click</button>
      </main>
    </body>
    </html>
  `;
  const findings = a11y.checkA11yStatic(badA11yHtml, [], {}, mk);
  const focusFinding = findings.find((f) => f.id === 'a11y-focus-visible');
  assert.ok(focusFinding, 'expected a11y-focus-visible finding on static stylesheet');
  assert.strictEqual(focusFinding.severity, 'medium');
});

test('checkEuCompliance recognizes Termly CMP and does not duplicate no-consent', () => {
  const termlyHtml = `
    <html>
    <head>
      <script src="https://app.termly.io/resource-blocker/12345"></script>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-123"></script>
    </head>
    <body>
      <div id="termly-code-snippet-support"></div>
    </body>
    </html>
  `;
  const meta = { trackers: ['Google Analytics'] };
  const findings = eu.checkEuCompliance(termlyHtml, { headers: {} }, [], meta, {}, mk);
  const noCmp = findings.find((f) => f.id === 'eu-no-cmp');
  assert.strictEqual(noCmp, undefined, 'expected no eu-no-cmp finding when Termly is detected');
  assert.ok(meta.eu.consentFrameworks.includes('CMP detected'), 'expected Termly to register as CMP detected');
});

test('detectWaf detects Vercel Security Checkpoint and suppresses content false positives', () => {
  const { detectWaf } = require('../lib/scanner.js');
  const vercelChallengeHtml = `
    <!DOCTYPE html><html><head><title>Vercel Security Checkpoint</title></head>
    <body><div id="root"><p id="header-text">Verify you are human</p></div></body></html>
  `;
  const res = {
    status: 403,
    headers: {
      server: 'Vercel',
      'x-vercel-mitigated': 'challenge',
      'x-vercel-challenge-token': 'token123',
    },
  };
  const waf = detectWaf(res, vercelChallengeHtml);
  assert.strictEqual(waf.isWaf, true);
  assert.strictEqual(waf.provider, 'Vercel');

  // Verify that checkEuCompliance returns empty when meta.isWafChallenge is true
  const meta = { isWafChallenge: true };
  const findings = eu.checkEuCompliance(vercelChallengeHtml, res, [], meta, {}, mk);
  assert.strictEqual(findings.length, 0, 'expected zero findings on WAF challenge page');
});

test('integrity enforces scoreCap 70 and Grade C on WAF-intercepted scan', () => {
  const integrity = require('../lib/integrity.js');
  const degraded = integrity.buildDegraded(['waf-intercepted'], 'Vercel WAF challenge');
  assert.ok(degraded, 'expected degraded object');
  assert.strictEqual(degraded.scoreCap, 70, 'WAF interception must cap score at 70');

  // Simulate report that artificially got 99 because checks did not run
  const fakeReport = {
    score: 99,
    grade: 'A+',
    findings: [],
  };
  integrity.applyDegraded(fakeReport, degraded);
  assert.strictEqual(fakeReport.score, 70, 'expected score to be capped at 70');
  assert.strictEqual(fakeReport.grade, 'C', 'expected grade to be degraded to C');
  assert.strictEqual(fakeReport.scoreUncapped, 99, 'expected scoreUncapped to record original 99');

  const finding = integrity.degradedFinding(degraded);
  assert.strictEqual(finding.id, 'scan-degraded');
  assert.strictEqual(finding.severity, 'medium');
});

