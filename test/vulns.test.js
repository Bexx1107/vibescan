'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { checkTech } = require('../lib/scanner');

test('checkTech detects EOL PHP runtime (< 8.2) with high severity', () => {
  const findings = [];
  const res = {
    headers: {
      'server': 'Apache/2.4.41 (Ubuntu)',
      'x-powered-by': 'PHP/7.4.33',
    },
  };
  checkTech(res, '<html><body></body></html>', findings, {});

  const phpFinding = findings.find((f) => f.id === 'vuln-php-eol');
  assert.ok(phpFinding, 'expected vuln-php-eol finding');
  assert.strictEqual(phpFinding.severity, 'high');
  assert.match(phpFinding.title, /End-of-Life PHP runtime/);
  assert.match(phpFinding.detail, /CVE-2024-4577/);
});

test('checkTech detects vulnerable Apache HTTP Server version (< 2.4.60)', () => {
  const findings = [];
  const res = {
    headers: {
      'server': 'Apache/2.4.52',
    },
  };
  checkTech(res, '<html><body></body></html>', findings, {});

  const apacheFinding = findings.find((f) => f.id === 'vuln-apache-outdated');
  assert.ok(apacheFinding, 'expected vuln-apache-outdated finding');
  assert.strictEqual(apacheFinding.severity, 'medium');
  assert.match(apacheFinding.detail, /CVE-2024-38472/);
});

test('checkTech detects EOL Node.js runtime (< 20)', () => {
  const findings = [];
  const res = {
    headers: {
      'x-powered-by': 'Express, Node.js v16.14.0',
    },
  };
  checkTech(res, '<html><body></body></html>', findings, {});

  const nodeFinding = findings.find((f) => f.id === 'vuln-nodejs-eol');
  assert.ok(nodeFinding, 'expected vuln-nodejs-eol finding');
  assert.strictEqual(nodeFinding.severity, 'medium');
});

test('checkTech detects vulnerable jQuery version (< 3.5.0)', () => {
  const findings = [];
  const res = { headers: {} };
  const html = '<html><head><script src="/assets/jquery-3.3.1.min.js"></script></head><body></body></html>';
  checkTech(res, html, findings, {});

  const jqFinding = findings.find((f) => f.id === 'vuln-jquery-outdated');
  assert.ok(jqFinding, 'expected vuln-jquery-outdated finding');
  assert.strictEqual(jqFinding.severity, 'medium');
  assert.match(jqFinding.detail, /CVE-2020-11022/);
});

test('checkTech detects malicious Polyfill.io / BootCDN script source (critical)', () => {
  const findings = [];
  const res = { headers: {} };
  const html = '<html><head><script src="https://cdn.polyfill.io/v3/polyfill.min.js?features=default"></script></head><body></body></html>';
  checkTech(res, html, findings, {});

  const polyFinding = findings.find((f) => f.id === 'vuln-polyfill-malicious');
  assert.ok(polyFinding, 'expected vuln-polyfill-malicious finding');
  assert.strictEqual(polyFinding.severity, 'critical');
  assert.match(polyFinding.detail, /CVE-2024-38521/);
});

test('checkTech detects outdated WordPress core (< 6.6.2)', () => {
  const findings = [];
  const res = { headers: {} };
  const html = '<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>';
  checkTech(res, html, findings, {});

  const wpFinding = findings.find((f) => f.id === 'vuln-wordpress-outdated');
  assert.ok(wpFinding, 'expected vuln-wordpress-outdated finding');
  assert.strictEqual(wpFinding.severity, 'high');
  assert.match(wpFinding.detail, /CVE-2024-4439/);
});

test('checkTech detects vulnerable Next.js (< 14.1.1) Server Actions SSRF', () => {
  const findings = [];
  const res = { headers: { 'x-nextjs-version': '13.4.19' } };
  const html = '<html><head></head><body><script id="__NEXT_DATA__" type="application/json">{"version":"13.4.19"}</script></body></html>';
  checkTech(res, html, findings, {});

  const nextFinding = findings.find((f) => f.id === 'vuln-nextjs-ssrf');
  assert.ok(nextFinding, 'expected vuln-nextjs-ssrf finding');
  assert.strictEqual(nextFinding.severity, 'high');
  assert.match(nextFinding.detail, /CVE-2024-34351/);
});

test('checkTech detects vulnerable Lodash (< 4.17.21) prototype pollution', () => {
  const findings = [];
  const res = { headers: {} };
  const html = '<html><head><script src="/js/lodash-4.17.15.min.js"></script></head><body></body></html>';
  checkTech(res, html, findings, {});

  const lodashFinding = findings.find((f) => f.id === 'vuln-lodash-outdated');
  assert.ok(lodashFinding, 'expected vuln-lodash-outdated finding');
  assert.strictEqual(lodashFinding.severity, 'medium');
  assert.match(lodashFinding.detail, /CVE-2020-8203/);
});

test('checkTech detects vulnerable Bootstrap (< 4.3.1) XSS', () => {
  const findings = [];
  const res = { headers: {} };
  const html = '<html><head><script src="/vendor/bootstrap-3.3.7.min.js"></script></head><body></body></html>';
  checkTech(res, html, findings, {});

  const bsFinding = findings.find((f) => f.id === 'vuln-bootstrap-outdated');
  assert.ok(bsFinding, 'expected vuln-bootstrap-outdated finding');
  assert.strictEqual(bsFinding.severity, 'medium');
  assert.match(bsFinding.detail, /CVE-2019-8331/);
});

test('checkTech detects outdated Moment.js (< 2.29.4) ReDoS', () => {
  const findings = [];
  const res = { headers: {} };
  const html = '<html><head><script src="/js/moment-2.24.0.min.js"></script></head><body></body></html>';
  checkTech(res, html, findings, {});

  const momentFinding = findings.find((f) => f.id === 'vuln-moment-redos');
  assert.ok(momentFinding, 'expected vuln-moment-redos finding');
  assert.strictEqual(momentFinding.severity, 'low');
  assert.match(momentFinding.detail, /CVE-2022-31129/);
});

test('checkTech detects outdated Axios (< 1.7.4) SSRF / redirect leak', () => {
  const findings = [];
  const res = { headers: {} };
  const html = '<html><head><script src="/static/axios-1.6.0.min.js"></script></head><body></body></html>';
  checkTech(res, html, findings, {});

  const axiosFinding = findings.find((f) => f.id === 'vuln-axios-outdated');
  assert.ok(axiosFinding, 'expected vuln-axios-outdated finding');
  assert.strictEqual(axiosFinding.severity, 'medium');
  assert.match(axiosFinding.detail, /CVE-2024-39338/);
});
