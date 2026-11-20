const test = require('node:test');
const assert = require('node:assert/strict');
const { scanSecrets } = require('../lib/scanner.js');
const { scanExtendedSecrets, scanPii, checkShodan } = require('../lib/probes.js');

test('scanSecrets detects real credentials and generic JWTs', () => {
  const awsText = 'const key = "AKIA1234567890ABCDEF";';
  const awsFound = scanSecrets(awsText);
  assert.equal(awsFound.length, 1);
  assert.match(awsFound[0], /AWS access key/);

  const realJwt = 'const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";';
  const jwtFound = scanSecrets(realJwt);
  assert.equal(jwtFound.length, 1);
  assert.match(jwtFound[0], /Generic bearer\/JWT/);
});

test('scanSecrets ignores Netlify CWV telemetry RUM tokens', () => {
  const netlifyHtml = '<script id="netlify-rum-container" data-netlify-cwv-token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaXRlX2lkIjoiM2EzNTUyZGUtNTE2Zi00MTVkLWE2ZDMtYjU4OWQ2MjdhZWU5IiwiYWNjb3VudF9pZCI6IjY5MjQ3OTM0ZGRhODJhNDU4MjFjMWUyOSIsImRlcGxveV9pZCI6IjZhYzcyNDdlMzY0OWYwMDAwOGRhNWI1NyIsImlzcyI6Im5ldGxpZnkifQ.3Gmxzpsc90KGq1jZ-S_97oF3qsiKZubw00RkBzgaJa4"></script>';
  const found = scanSecrets(netlifyHtml);
  assert.deepEqual(found, [], 'Netlify CWV telemetry token must not be flagged as a secret leak');
});

test('scanExtendedSecrets ignores Netlify CWV tokens in bundles', () => {
  const netlifyBundle = 'var cwv = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaXRlX2lkIjoiM2EzNTUyZGUtNTE2Zi00MTVkLWE2ZDMtYjU4OWQ2MjdhZWU5IiwiYWNjb3VudF9pZCI6IjY5MjQ3OTM0ZGRhODJhNDU4MjFjMWUyOSIsImRlcGxveV9pZCI6IjZhYzcyNDdlMzY0OWYwMDAwOGRhNWI1NyIsImlzcyI6Im5ldGxpZnkifQ.3Gmxzpsc90KGq1jZ-S_97oF3qsiKZubw00RkBzgaJa4";';
  const found = scanExtendedSecrets(netlifyBundle);
  assert.deepEqual(found, [], 'Extended scanner must not flag Netlify CWV token');
});

test('scanSecrets and scanExtendedSecrets ignore public Supabase anon key', () => {
  // Synthetic Supabase anon key fixture (`role: anon` payload)
  const payload = Buffer.from(
    JSON.stringify({ iss: 'supabase', ref: 'demo123', role: 'anon', iat: 1700000000, exp: 2000000000 })
  ).toString('base64url');
  const anonKey = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.syntheticSignatureForUnitTestOnly123`;
  const code = `const supabase = createClient("https://demo123.supabase.co", "${anonKey}");`;
  
  const foundSecrets = scanSecrets(code);
  assert.deepEqual(foundSecrets, [], 'Public Supabase anon key must not be flagged as Generic bearer/JWT');

  const foundExt = scanExtendedSecrets(code);
  assert.deepEqual(foundExt, [], 'Public Supabase anon key must not be flagged as Supabase service key');
});

test('scanExtendedSecrets still detects actual Supabase service_role key', () => {
  // Service role key with role: service_role
  // {"iss":"supabase","ref":"proj123","role":"service_role","iat":1700000000,"exp":2000000000}
  const serviceKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2oxMjMiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.signature1234567890abcdef';
  const code = `const supabaseAdmin = createClient("https://proj123.supabase.co", "${serviceKey}");`;

  const foundExt = scanExtendedSecrets(code);
  assert.equal(foundExt.length, 1);
  assert.equal(foundExt[0].name, 'Supabase service key');
});

test('scanPii ignores floating-point numbers and SVG coordinates (false positive credit card)', () => {
  const svgText = 'matrix(1.089465234375 0.5170648437500001 2.370432421875 0.42404140625)';
  const found = scanPii(svgText);
  const cards = found.filter((p) => p.name === 'Credit-card-shaped number');
  assert.deepEqual(cards, [], 'Floating point coordinate 0.5170648437500001 must not trigger credit card alert');
});

test('scanPii still detects genuine credit card numbers', () => {
  // 5170 6484 3750 0001 passes Luhn
  const cardText = 'Payment details: card number 5170 6484 3750 0001 expiring 12/28';
  const found = scanPii(cardText);
  const cards = found.filter((p) => p.name === 'Credit-card-shaped number');
  assert.equal(cards.length, 1);
});

test('checkShodan suppresses exposed DB port on shared cPanel hosting gateways', async () => {
  const findings = [];
  const meta = {};
  const mk = (id, severity, title, detail, fix, evidence) => ({ id, severity, title, detail, fix, evidence });

  // Mock global fetch to return shared cPanel InternetDB data
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    status: 200,
    json: async () => ({
      ip: '93.184.216.34',
      ports: [80, 443, 465, 2083, 2087, 3306],
      hostnames: ['shared01.cpanel-host.example', 'tenant.com'],
      cpes: ['cpe:/a:mariadb:mariadb:11.4.13'],
      tags: ['database'],
      vulns: []
    })
  });

  try {
    await checkShodan('93.184.216.34', findings, meta, mk);
    const dbFinding = findings.find((f) => f.id === 'shodan-exposed-db');
    assert.equal(dbFinding, undefined, 'Shared cPanel hosting gateway must not flag shodan-exposed-db');
    assert.equal(meta.shodan.isSharedHosting, true, 'isSharedHosting must be true');
  } finally {
    global.fetch = originalFetch;
  }
});
