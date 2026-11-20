'use strict';
/**
 * Fixture tests for the provenance verification engine (PLAN-LEADERBOARD.md §8,
 * Phase 2). Runs with the built-in node:test — no dependencies.
 *
 *   node --test test/verify.test.js
 *
 * The tests encode the operator decision of 2026-10-22: harness and model are
 * NEVER verified, and weak AI signals never contradict a hand-built claim.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { verifyClaim, nameOverlap, aiEvidence } = require('../lib/verify');
const buildfp = require('../lib/buildfp');

/** Build a fake report whose meta.build matches what buildfp.collect produces. */
function report(build) {
  return { target: 'https://x.si', meta: { build } };
}

const WP = { platform: 'wordpress', generator: ['WordPress 6.4'] };
const NEXT_SHADCN = {
  platform: 'nextjs',
  assets: ['/_next/static/chunks/app/page.js', '/assets/shadcn.css'],
  flags: { shadcn: true, tailwind4: true, lucide: true, appRouter: true },
};
const V0 = {
  platform: 'nextjs',
  flags: { shadcn: true, tailwind4: true, v0Badge: true },
};

/* ------------------------------------------------------------------ *
 * 1. The hard rule
 * ------------------------------------------------------------------ */

test('harness and model are never verified, even with a perfect fingerprint', () => {
  const r = verifyClaim(
    { builderKind: 'ai', harness: 'claude-code', model: 'claude-opus', platform: 'nextjs' },
    report(V0)
  );
  assert.equal(r.contradictions.length, 0);
  assert.equal(r.verification, 'verified');
  assert.deepEqual(Object.keys(r.fields).sort(), ['builderKind', 'platform']);
  // The verdict is about builderKind/platform — the return value never carries
  // a verdict about harness or model at all.
  assert.deepEqual(r.verifiableFields, ['builderKind', 'builderName', 'platform']);
  assert.ok(!('harness' in r));
  assert.ok(!('model' in r));
});

test('a model claim alone cannot reach verified', () => {
  const r = verifyClaim(
    { builderKind: 'unknown', model: 'gpt-5' },
    report({ platform: null, flags: {} })
  );
  assert.equal(r.verification, 'unverified');
  assert.equal(r.confidence, 0);
});

/* ------------------------------------------------------------------ *
 * 2. Platform
 * ------------------------------------------------------------------ */

test('wordpress fingerprint verifies the platform claim', () => {
  const r = verifyClaim({ platform: 'wordpress' }, report(WP));
  assert.equal(r.verification, 'verified');
  assert.equal(r.platform, 'wordpress');
  assert.equal(r.confidence, 95);
});

test('platform mismatch is disputed', () => {
  const r = verifyClaim({ builderKind: 'agency', platform: 'wordpress' }, report(NEXT_SHADCN));
  assert.equal(r.verification, 'disputed');
  assert.match(r.contradictions[0], /wordpress/i);
});

test('custom platform claim is compatible with nextjs framework', () => {
  const r = verifyClaim({ builderKind: 'ai', platform: 'custom' }, report(NEXT_SHADCN));
  assert.equal(r.fields.platform.status, 'verified');
  assert.equal(r.contradictions.length, 0);
  assert.notEqual(r.verification, 'disputed');
});

test('custom platform claim is disputed if site fingerprints as wordpress CMS', () => {
  const r = verifyClaim({ builderKind: 'solo', platform: 'custom' }, report(WP));
  assert.equal(r.fields.platform.status, 'disputed');
  assert.equal(r.verification, 'disputed');
});

/* ------------------------------------------------------------------ *
 * 3. AI artefacts
 * ------------------------------------------------------------------ */

test('v0 badge verifies an AI claim', () => {
  const r = verifyClaim({ builderKind: 'ai' }, report(V0));
  assert.equal(r.verification, 'verified');
  assert.equal(r.stackHint.level, 'likely-ai');
});

test('v0 badge disputes an agency claim', () => {
  const r = verifyClaim({ builderKind: 'agency', builderName: 'Studio Primer' }, report(V0));
  assert.equal(r.verification, 'disputed');
});

test('exposed agent file verifies an AI claim and disputes a human one', () => {
  const fp = { platform: null, flags: {}, agentFiles: ['/CLAUDE.md'] };
  assert.equal(verifyClaim({ builderKind: 'ai' }, report(fp)).verification, 'verified');
  assert.equal(verifyClaim({ builderKind: 'solo' }, report(fp)).verification, 'disputed');
});

test('weak signals alone NEVER contradict a hand-built claim', () => {
  const r = verifyClaim({ builderKind: 'agency', platform: 'nextjs' }, report(NEXT_SHADCN));
  assert.equal(r.verification, 'unverified');
  assert.equal(r.fields.platform.status, 'verified');
  assert.equal(r.fields.builderKind.status, 'unverified',
    'style cannot prove or disprove "agency", it only fails to support it');
  assert.equal(r.contradictions.length, 0);
  assert.equal(r.stackHint.level, 'weak-ai');
});

test('a verified platform does not leak confidence into an unrelated field', () => {
  const r = verifyClaim({ builderKind: 'agency', builderName: 'Nihče d.o.o.' }, report(WP));
  assert.equal(r.fields.platform, undefined, 'platform was not claimed');
  assert.equal(r.fields.builderName.status, 'unverified');
  assert.equal(r.verification, 'unverified');
  assert.equal(r.confidence, 0, 'weakest claimed field decides the headline');
});

test('weak signals alone cannot verify an AI claim either', () => {
  // No platform claim, so the Next.js fingerprint contributes nothing here.
  // 14+10+8+6 = 38 < 55 — style alone must not be enough to be labelled AI.
  const r = verifyClaim({ builderKind: 'ai' }, report(NEXT_SHADCN));
  assert.equal(r.verification, 'unverified');
  assert.equal(r.confidence, 38);
  assert.equal(r.stackHint.level, 'weak-ai');
});

/* ------------------------------------------------------------------ *
 * 4. Builder name
 * ------------------------------------------------------------------ */

test('builder name in the footer verifies', () => {
  const fp = {
    platform: 'wordpress',
    footerText: '© 2026 Brandco Studio d.o.o. Vse pravice pridržane.',
  };
  const r = verifyClaim({ builderKind: 'agency', builderName: 'Brandco Studio' }, report(fp));
  assert.equal(r.verification, 'verified');
  assert.ok(r.evidence.some((e) => /footer/i.test(e)));
});

test('builder name in JSON-LD verifies, and a company credit verifies "agency"', () => {
  const fp = { platform: 'nextjs', jsonLdNames: ['Epix d.o.o.'] };
  const r = verifyClaim({ builderKind: 'agency', builderName: 'Epix' }, report(fp));
  assert.equal(r.fields.builderName.status, 'verified');
  assert.equal(r.fields.builderKind.status, 'verified', 'd.o.o. reads as a company');
  assert.equal(r.verification, 'verified');
});

test('a generic shared word does not verify a wrong agency', () => {
  const fp = { platform: 'wordpress', footerText: 'Made by Pixel Studio, Ljubljana' };
  const r = verifyClaim(
    { builderKind: 'agency', builderName: 'Nova Studio Digital' },
    report(fp)
  );
  assert.equal(r.fields.builderName.status, 'unverified');
  assert.equal(
    r.verification,
    'unverified',
    'the name is unsupported, so the submission earns no badge'
  );
  assert.ok(
    !r.evidence.some((e) => /name appears|name matches/i.test(e)),
    'the name must not be credited'
  );
});

test('missing credit is unverified, not disputed', () => {
  const r = verifyClaim(
    { builderKind: 'agency', builderName: 'Nihče d.o.o.' },
    report({ platform: null, flags: {} })
  );
  assert.equal(r.verification, 'unverified');
  assert.equal(r.contradictions.length, 0);
});

/* ------------------------------------------------------------------ *
 * 5. Name matching unit tests
 * ------------------------------------------------------------------ */

test('nameOverlap tolerates legal suffixes but not generic overlap', () => {
  assert.ok(nameOverlap('Brandco', 'Brandco Studio d.o.o.') >= 0.7);
  assert.ok(nameOverlap('Epix', 'EPIX d.o.o.') >= 0.7);
  assert.ok(nameOverlap('Nova Studio Digital', 'Pixel Studio') < 0.7);
  assert.equal(nameOverlap('', 'anything'), 0);
});

/* ------------------------------------------------------------------ *
 * 6. Fingerprint collector
 * ------------------------------------------------------------------ */

test('buildfp detects wordpress and next from HTML', () => {
  assert.equal(buildfp.detectPlatform('<link href="/wp-content/x.css">'), 'wordpress');
  assert.equal(buildfp.detectPlatform('<script src="/_next/static/x.js">'), 'nextjs');
  assert.equal(buildfp.detectPlatform('<html><body>hi</body></html>'), null);
});

test('self-disclosure verifies an AI claim but never contradicts a human one', () => {
  const fp = { platform: null, flags: { selfDeclaredAI: true } };
  const ai = verifyClaim({ builderKind: 'ai' }, report(fp));
  assert.equal(ai.fields.builderKind.status, 'verified', 'the author said so themselves');
  assert.equal(ai.confidence, 60);
  assert.equal(ai.stackHint.level, 'likely-ai');
  assert.ok(ai.evidence.some((e) => /explicitly discloses/i.test(e)));

  const human = verifyClaim({ builderKind: 'agency' }, report(fp));
  assert.equal(human.verification, 'unverified');
  assert.equal(human.contradictions.length, 0, 'a disclosure is not a contradiction');
});

test('buildfp detects self-disclosure in Slovenian and English', () => {
  assert.equal(buildfp.selfDeclaredAI('Zgrajeno s strojem'), true);
  assert.equal(buildfp.selfDeclaredAI('Built with AI'), true);
  assert.equal(buildfp.selfDeclaredAI('Zgradili smo hišo'), false);
});

test('buildfp resolves same-origin absolute assets to a path', () => {
  const html = '<script src="https://site.si/_next/static/chunks/app/x.js"></script>' +
               '<script src="https://cdn.other.com/track.js"></script>';
  const paths = buildfp.assetPaths(html, 'https://site.si');
  assert.deepEqual(paths, ['/_next/static/chunks/app/x.js']);
});

test('buildfp flags badges without flagging ordinary tailwind as a badge', () => {
  const f = buildfp.aiFlags('<div class="bg-indigo-500">x</div>', ['/assets/tailwind.css']);
  assert.equal(f.v0Badge, false);
  assert.equal(f.tailwind4, true);
  assert.equal(buildfp.aiFlags('built with v0', []).v0Badge, true);
});

test('buildfp extracts only the footer, and bounds its length', () => {
  const html = `<header>Nav</header><footer>© 2026 <b>Acme</b> d.o.o.</footer>`;
  const text = buildfp.footerText(html);
  assert.equal(text, '© 2026 Acme d.o.o.');
  assert.equal(buildfp.footerText('<header>no footer</header>'), null);
});

test('buildfp never returns raw HTML in the fingerprint', async () => {
  const html = `<html><head><meta name="generator" content="WordPress 6.4"></head>
    <body><footer>Acme d.o.o.</footer><script>${'x'.repeat(5000)}</script></body></html>`;
  const fp = await buildfp.collect(html, { url: 'https://example.si/' }, null);
  const serialised = JSON.stringify(fp);
  assert.ok(!serialised.includes('<footer>'), 'markup must be stripped');
  assert.ok(!serialised.includes('xxxxx'), 'script bodies must be dropped');
  assert.ok(serialised.length < 6000, 'fingerprint must stay small');
  assert.equal(fp.platform, 'wordpress');
});

/* ------------------------------------------------------------------ *
 * 7. CSP & Asset Host Agency Footprints
 * ------------------------------------------------------------------ */

test('buildfp extracts hostnames from Content-Security-Policy headers', async () => {
  const res = {
    url: 'https://www.shop-example.si/',
    headers: {
      'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cdn.northstar.serv.example https://www.google-analytics.com; style-src 'self' *.northstar.example;"
    }
  };
  const html = '<html><body>Example Shop</body></html>';
  const fp = await buildfp.collect(html, res, null);
  assert.ok(Array.isArray(fp.cspHosts));
  assert.ok(fp.cspHosts.includes('static.cdn.northstar.serv.example'));
  assert.ok(fp.cspHosts.includes('northstar.example'));
  assert.ok(fp.cspHosts.includes('www.google-analytics.com'));
});

test('buildfp extracts hostnames from HTML script/link tags', async () => {
  const html = '<html><head><script src="https://static.cdn.northstar.serv.example/js/theme.js"></script></head><body></body></html>';
  const fp = await buildfp.collect(html, { url: 'https://www.shop-example.si/' }, null);
  assert.ok(Array.isArray(fp.assetHosts));
  assert.ok(fp.assetHosts.includes('static.cdn.northstar.serv.example'));
});

test('builder name matches CSP hostname for Northstar on shop-example.si', () => {
  const fp = {
    platform: null,
    cspHosts: ['static.cdn.northstar.serv.example', 'www.google-analytics.com'],
  };
  const r = verifyClaim({ builderKind: 'agency', builderName: 'Northstar' }, report(fp));
  assert.equal(r.fields.builderName.status, 'verified');
  assert.equal(r.fields.builderName.confidence, 85);
  assert.equal(r.fields.builderKind.status, 'verified');
  assert.equal(r.verification, 'verified');
  assert.ok(r.evidence.some((e) => /Builder name matches asset\/infrastructure hostname in CSP or scripts/i.test(e)));
});

test('builder name matches infrastructure domain when kind is unknown', () => {
  const fp = {
    cspHosts: ['static.cdn.northstar.serv.example'],
  };
  const r = verifyClaim({ builderKind: 'unknown', builderName: 'Northstar' }, report(fp));
  assert.equal(r.fields.builderName.status, 'verified');
  assert.equal(r.fields.builderName.confidence, 85);
  assert.equal(r.verification, 'verified');
});

test('generic infrastructure tokens (cdn, static) do not falsely verify an agency name', () => {
  const fp = {
    cspHosts: ['static.cdn.cloudflare.net', 'assets.example.com'],
  };
  const r = verifyClaim({ builderKind: 'agency', builderName: 'Static' }, report(fp));
  assert.equal(r.fields.builderName.status, 'unverified');
  assert.equal(r.verification, 'unverified');
});

test('buildfp flags ignore form dropdown options (Bolt.new, Create.xyz, v0)', () => {
  const html = `
    <form>
      <select name="harness">
        <option value="Bolt.new">Bolt.new (StackBlitz)</option>
        <option value="Create.xyz">Create.xyz</option>
        <option value="v0">v0 by Vercel</option>
      </select>
    </form>
    <div class="content">Regular content</div>
  `;
  const flags = buildfp.aiFlags(html, []);
  assert.equal(flags.boltBadge, false);
  assert.equal(flags.createXyzBadge, false);
  assert.equal(flags.v0Badge, false);
});

test('detectTech does not falsely flag Google Fonts or Vercel from CSP headers or select dropdowns', () => {
  const { detectTech } = require('../lib/scanner');
  const res = {
    headers: {
      'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:;",
      server: 'Caddy',
    },
  };
  const body = `
    <html>
      <head><link rel="stylesheet" href="/styles.css"></head>
      <body>
        <select><option value="v0">v0 by Vercel</option></select>
      </body>
    </html>
  `;
  const tech = detectTech(res, body);
  assert.ok(!tech.includes('Google Fonts'), 'Google Fonts must not be detected from CSP header alone');
  assert.ok(!tech.includes('Vercel'), 'Vercel must not be detected from select dropdown text');
  assert.ok(tech.includes('Server: Caddy'));
});

test('detectTech flags Google Fonts when link tag is present in body', () => {
  const { detectTech } = require('../lib/scanner');
  const res = { headers: {} };
  const body = `<html><head><link href="https://fonts.googleapis.com/css2?family=Roboto" rel="stylesheet"></head></html>`;
  const tech = detectTech(res, body);
  assert.ok(tech.includes('Google Fonts'));
});
