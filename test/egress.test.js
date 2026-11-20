'use strict';
/**
 * Tiered scanner egress tests.
 *
 * The failure mode here is security-relevant, not cosmetic: if parsing degrades
 * into "no tier" the request would leave from the scan host's own address
 * (which may co-host other services on the same server).
 * So: the parser never invents a tier, and the breaker never leaks across hosts.
 */

const test = require('node:test');
const assert = require('node:assert');

function fresh() {
  delete require.cache[require.resolve('../lib/egress')];
  return require('../lib/egress');
}

function withEnv(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) {
    saved[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  try {
    return fn();
  } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

const EMPTY = { SCANNER_EGRESS: undefined, SCANNER_PROXIES: undefined, SCANNER_PROXY: undefined, SCANNER_ALLOW_DIRECT: undefined };

test('named SCANNER_EGRESS keeps order and names', () => {
  withEnv({ ...EMPTY, SCANNER_EGRESS: 'vpn=http://127.0.0.1:8888,res=http://127.0.0.1:8889' }, () => {
    assert.deepStrictEqual(fresh().tiers().map((t) => [t.name, t.url]), [
      ['vpn', 'http://127.0.0.1:8888'],
      ['res', 'http://127.0.0.1:8889'],
    ]);
  });
});

test('positional SCANNER_PROXIES gets stable auto names', () => {
  withEnv({ ...EMPTY, SCANNER_PROXIES: 'http://127.0.0.1:8888,http://127.0.0.1:8889' }, () => {
    assert.deepStrictEqual(fresh().tiers().map((t) => [t.name, t.url]), [
      ['tier1', 'http://127.0.0.1:8888'],
      ['tier2', 'http://127.0.0.1:8889'],
    ]);
  });
});

test('legacy SCANNER_PROXY still yields exactly one tier', () => {
  withEnv({ ...EMPTY, SCANNER_PROXY: 'http://127.0.0.1:8888' }, () => {
    const t = fresh().tiers();
    assert.strictEqual(t.length, 1);
    assert.strictEqual(t[0].url, 'http://127.0.0.1:8888');
  });
});

test('no config yields no tiers — a direct path is never invented', () => {
  withEnv(EMPTY, () => assert.deepStrictEqual(fresh().tiers(), []));
});

test('the direct tier is refused unless explicitly allowed', () => {
  withEnv({ ...EMPTY, SCANNER_PROXIES: 'http://127.0.0.1:8888,direct' }, () => {
    assert.deepStrictEqual(fresh().tiers().map((t) => t.url), ['http://127.0.0.1:8888']);
  });
  withEnv({ ...EMPTY, SCANNER_PROXIES: 'http://127.0.0.1:8888,direct', SCANNER_ALLOW_DIRECT: '1' }, () => {
    assert.deepStrictEqual(fresh().tiers().map((t) => t.url), ['http://127.0.0.1:8888', '']);
  });
});

test('a typo can never become a silent direct connection', () => {
  withEnv({ ...EMPTY, SCANNER_PROXIES: 'htp://127.0.0.1:8888,dirct' }, () => {
    assert.deepStrictEqual(fresh().tiers(), []);
  });
});

test('only connection-level errors count as tier failures', () => {
  const e = fresh();
  assert.strictEqual(e.isTierFailure(new Error('read ECONNRESET')), true);
  assert.strictEqual(e.isNetError(new Error('socket hang up')), true);
  assert.strictEqual(e.isTierFailure(new Error('Proxy CONNECT failed: 502 Bad Gateway')), true);
  assert.strictEqual(e.isTierFailure(new Error('write EPIPE')), true);
  assert.strictEqual(e.isTierFailure(new Error('Request timed out after 20000ms')), true);
  assert.strictEqual(e.isTierFailure(new Error('ETIMEDOUT')), true);
  assert.strictEqual(e.isTierFailure(new Error('Invalid URL')), false);
});

test('breaker opens after 3 failures, scoped to that host and tier only', () => {
  withEnv({ ...EMPTY, SCANNER_EGRESS: 'vpn=http://127.0.0.1:8888,res=http://127.0.0.1:8889' }, () => {
    const e = fresh();
    const err = new Error('read ECONNRESET');
    for (let i = 0; i < 3; i++) e.noteFailure('blocked.example', 'vpn', err);

    assert.ok(e.tripped('blocked.example', 'vpn'));
    assert.ok(e.isOpen('blocked.example', 'vpn'));
    assert.strictEqual(e.isOpen('other.example', 'vpn'), null, 'must not leak across hosts');
    assert.strictEqual(e.isOpen('blocked.example', 'res'), null, 'must not leak across tiers');

    assert.deepStrictEqual(e.availableTiers('blocked.example').map((t) => t.name), ['res']);
    assert.deepStrictEqual(e.plan('other.example').map((t) => t.name), ['vpn', 'res']);
  });
});

test('a success closes the breaker and records the proven exit', () => {
  withEnv({ ...EMPTY, SCANNER_EGRESS: 'vpn=http://127.0.0.1:8888,res=http://127.0.0.1:8889' }, () => {
    const e = fresh();
    const err = new Error('read ECONNRESET');
    for (let i = 0; i < 4; i++) e.noteFailure('x.example', 'vpn', err);
    e.noteSuccess('x.example', 'res');
    assert.ok(e.isOpen('x.example', 'vpn'), 'a success on ONE tier must not clear another tier');
    assert.strictEqual(e.isOpen('x.example', 'res'), null);
    assert.strictEqual(e.currentProxy(), 'http://127.0.0.1:8889');
    e.noteSuccess('x.example', 'vpn');
    assert.strictEqual(e.isOpen('x.example', 'vpn'), null, 'its own success does clear it');
  });
});

test('chromeProxyFor skips a tripped tier', () => {
  withEnv({ ...EMPTY, SCANNER_EGRESS: 'vpn=http://127.0.0.1:8888,res=http://127.0.0.1:8889' }, () => {
    const e = fresh();
    const err = new Error('read ECONNRESET');
    for (let i = 0; i < 3; i++) e.noteFailure('h.example', 'vpn', err);
    assert.strictEqual(e.chromeProxyFor('h.example'), 'http://127.0.0.1:8889');
  });
});

test('plan prioritizes host proven proxy once established', () => {
  withEnv({ ...EMPTY, SCANNER_EGRESS: 'vpn=http://127.0.0.1:8888,res=http://127.0.0.1:8889' }, () => {
    const e = fresh();
    assert.deepStrictEqual(e.plan('test.example').map((t) => t.name), ['vpn', 'res']);
    e.noteSuccess('test.example', 'res');
    assert.deepStrictEqual(e.plan('test.example').map((t) => t.name), ['res', 'vpn']);
    assert.deepStrictEqual(e.plan('other.example').map((t) => t.name), ['res', 'vpn']);
  });
});

test('exhaustedError is distinguishable from a target block', () => {
  const err = fresh().exhaustedError('h.example', ['vpn', 'res']);
  assert.strictEqual(err.code, 'ERR_EGRESS_ALL_TIERS_OPEN');
  assert.match(err.message, /vpn, res/);
});
