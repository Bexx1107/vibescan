'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { checkSubdomains, resolveSubdomainDns } = require('../lib/ct-recon');
const { checkShodan } = require('../lib/probes');

test('resolveSubdomainDns classifies non-existent domain as NXDOMAIN/HISTORICAL', async () => {
  const res = await resolveSubdomainDns('nonexistent-subdomain-12345xyz99.si', 1000);
  assert.equal(res.live, false);
  assert.ok(res.status === 'NXDOMAIN' || res.status === 'HISTORICAL');
});

test('checkShodan lists all CVEs in finding evidence rather than truncating at 10', async () => {
  const fakeVulns = [
    'CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003', 'CVE-2026-0004', 'CVE-2026-0005',
    'CVE-2026-0006', 'CVE-2026-0007', 'CVE-2026-0008', 'CVE-2026-0009', 'CVE-2026-0010',
    'CVE-2026-0011', 'CVE-2026-0012', 'CVE-2026-0013', 'CVE-2026-0014', 'CVE-2026-0015',
  ];

  const originalFetch = global.fetch;
  global.fetch = async () => ({
    status: 200,
    json: async () => ({
      ip: '93.184.216.34',
      ports: [22, 80, 443],
      cpes: [],
      hostnames: ['example.com'],
      tags: [],
      vulns: fakeVulns,
    }),
  });

  try {
    const findings = [];
    const meta = {};
    const mk = (id, severity, title, detail, fix, evidence) => ({ id, severity, title, detail, fix, evidence });

    await checkShodan('93.184.216.34', findings, meta, mk);

    const cveFinding = findings.find((f) => f.id === 'shodan-known-cve');
    assert.ok(cveFinding, 'shodan-known-cve finding generated');
    assert.ok(cveFinding.evidence.includes('CVE-2026-0011'), 'evidence contains CVEs past index 10');
    assert.ok(cveFinding.evidence.includes('CVE-2026-0015'), 'evidence contains all 15 CVEs');
    assert.ok(cveFinding.evidence.includes('15 total'), 'evidence reports total count');
  } finally {
    global.fetch = originalFetch;
  }
});

test('checkSubdomains sets meta.ct.all and meta.ct.subdomains with full list and evidence status', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    text: async () => JSON.stringify([
      'test.example.internal',
      'dev.example.internal',
      'admin.example.internal',
      'www.example.internal',
      'example.internal'
    ]),
  });

  try {
    const findings = [];
    const meta = {};
    const mk = (id, severity, title, detail, fix, evidence) => ({ id, severity, title, detail, fix, evidence });

    await checkSubdomains('example.internal', findings, meta, mk);

    assert.ok(meta.ct, 'meta.ct populated');
    assert.equal(meta.ct.count, 5);
    assert.ok(Array.isArray(meta.ct.subdomains) && meta.ct.subdomains.length === 5, 'meta.ct.subdomains has all 5');
    assert.ok(Array.isArray(meta.ct.all) && meta.ct.all.length === 5, 'meta.ct.all has all 5');
    assert.ok(meta.ct.staging.includes('test.example.internal'));

    const stagingFinding = findings.find((f) => f.id === 'ct-exposed-staging');
    assert.ok(stagingFinding, 'ct-exposed-staging finding generated');
    assert.ok(stagingFinding.evidence.includes('test.example.internal'));
    assert.ok(stagingFinding.evidence.includes('NXDOMAIN') || stagingFinding.evidence.includes('LIVE') || stagingFinding.evidence.includes('HISTORICAL'));
  } finally {
    global.fetch = originalFetch;
  }
});
