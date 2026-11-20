'use strict';
/**
 * Ordered egress tier chain for the scanner.
 *
 * Why: the scanner previously had a single outbound path, so a target that drops
 * or tar-pits TLS handshakes made the site unscannable — every probe paid that
 * connect timeout stall across the whole scan.
 *
 * Tiers are tried in order, but ONLY on connection-level failures. A 403/429 or
 * a WAF challenge is a real answer from a reachable server; retrying it on
 * another exit would turn a truthful "this site blocks automated scanners"
 * finding into ban evasion. That distinction is the whole point of
 * isTierFailure().
 *
 * SECURITY: no direct tier is ever invented. A proxy-less request leaves from
 * the host's own public IP (which may co-host other services), and an abuse
 * complaint there costs far more than a failed scan. Direct is only possible
 * when an operator names `direct` in the list AND sets SCANNER_ALLOW_DIRECT=1,
 * or when the caller explicitly passes bypassProxy.
 *
 * Config (first one that is set wins):
 *   SCANNER_EGRESS="vpn=http://127.0.0.1:8888,res=http://127.0.0.1:8889"
 *   SCANNER_PROXIES="http://127.0.0.1:8888,http://127.0.0.1:8889"   (positional)
 *   SCANNER_PROXY="http://127.0.0.1:8888"                          (legacy, single)
 */

const FAILS_BEFORE_OPEN = 3;
const COOLDOWN_MS = 60 * 1000;

/**
 * Connection-level network failures and handshake/socket timeouts.
 * When a target drops or tar-pits TLS handshakes (e.g. anti-bot/VPN blocks),
 * Node emits 'Request timed out after ...ms'. Matching timeout errors ensures
 * the scanner fails over to the residential exit instead of stalling for minutes.
 */
const NET_ERROR =
  /econnreset|econnrefused|econnaborted|etimedout|timed?\s*out|err_socket_timeout|esockettimedout|ehostunreach|enetunreach|eai_again|epipe|socket hang up|socket disconnected|unexpected eof|proxy connect|connect failed|broken pipe|tunnel connection failed/i;

/** `${hostname}|${tierName}` -> { count, openedAt, sample } */
const fails = new Map();

/** Exit that last carried a request successfully, for the Chrome phases. */
let provenProxy = null;
const provenByHost = new Map();

function usable(value) {
  return /^https?:\/\/[^\s]+$/i.test(String(value || '').trim());
}

function normalize(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function makeTier(name, url) {
  const tier = { name, url };
  // Compatibility aliases for older call sites. Non-enumerable so they never
  // appear in deepStrictEqual comparisons of the tier objects themselves.
  Object.defineProperty(tier, 'id', { value: name, enumerable: false });
  Object.defineProperty(tier, 'proxy', { value: url, enumerable: false });
  return tier;
}

function pushTier(out, seen, name, raw) {
  const item = String(raw || '').trim();
  if (!item) return;

  if (item.toLowerCase() === 'direct') {
    const allowed = String(process.env.SCANNER_ALLOW_DIRECT || '').trim() === '1';
    if (!allowed) return; // refused by default: see SECURITY note above
    if (seen.has('direct')) return;
    seen.add('direct');
    out.push(makeTier(name, ''));
    return;
  }

  if (!usable(item)) return; // a typo must never degrade into a direct hop
  const url = normalize(item);
  if (seen.has(url)) return;
  seen.add(url);
  out.push(makeTier(name, url));
}

/**
 * The configured chain, in order. Returns [] when nothing usable is
 * configured — it never invents a tier.
 */
function tiers() {
  const named = String(process.env.SCANNER_EGRESS || '').trim();
  const positional = String(process.env.SCANNER_PROXIES || '').trim();
  const legacy = String(process.env.SCANNER_PROXY || '').trim();

  const out = [];
  const seen = new Set();

  if (named) {
    let i = 0;
    for (const chunk of named.split(',')) {
      const item = chunk.trim();
      if (!item) continue;
      i += 1;
      const eq = item.indexOf('=');
      if (eq > 0) {
        pushTier(out, seen, item.slice(0, eq).trim() || `tier${i}`, item.slice(eq + 1));
      } else {
        const autoName = item.toLowerCase() === 'direct' ? 'direct' : `tier${i}`;
        pushTier(out, seen, autoName, item);
      }
    }
    return out;
  }

  if (positional) {
    let i = 0;
    for (const chunk of positional.split(',')) {
      const item = chunk.trim();
      if (!item) continue;
      i += 1;
      pushTier(out, seen, `tier${i}`, item);
    }
    return out;
  }

  if (legacy) pushTier(out, seen, 'proxy', legacy);
  return out;
}

function isTierFailure(err) {
  const msg = String((err && err.message) || err || '');
  return NET_ERROR.test(msg);
}

function key(hostname, tierName) {
  return `${String(hostname || '').toLowerCase()}|${tierName}`;
}

/** Open breaker for this host+tier, or null. Expires after COOLDOWN_MS. */
function isOpen(hostname, tierName) {
  const k = key(hostname, tierName);
  const s = fails.get(k);
  if (!s || !s.openedAt) return null;
  if (Date.now() - s.openedAt >= COOLDOWN_MS) {
    fails.delete(k);
    return null;
  }
  return s;
}

const tripped = isOpen;

function noteFailure(hostname, tierName, err) {
  if (!isTierFailure(err)) return null;
  const k = key(hostname, tierName);
  const s = fails.get(k) || { count: 0, openedAt: 0, sample: '' };
  s.count += 1;
  s.sample = String((err && err.message) || err || '');
  if (s.count >= FAILS_BEFORE_OPEN && !s.openedAt) s.openedAt = Date.now();
  fails.set(k, s);
  return s;
}

/**
 * A success clears the breaker for THAT tier only — one tier answering says
 * nothing about whether another exit is reachable — and records which exit
 * actually worked so the Chrome phases can follow it.
 */
function noteSuccess(hostname, tierName) {
  fails.delete(key(hostname, tierName));
  const tier = tiers().find((t) => t.name === tierName);
  if (tier) {
    provenProxy = tier.url;
    if (hostname) provenByHost.set(String(hostname).toLowerCase(), tier.name);
  }
  return tier ? tier.url : null;
}

/** Tiers still worth trying for this host, in configured order (with proven working tier prioritized first). */
function plan(hostname) {
  const usable = tiers().filter((t) => !isOpen(hostname, t.name));
  const hostProvenTierName = hostname && provenByHost.get(String(hostname).toLowerCase());
  if (hostProvenTierName) {
    const idx = usable.findIndex((t) => t.name === hostProvenTierName);
    if (idx > 0) {
      const [hit] = usable.splice(idx, 1);
      usable.unshift(hit);
    }
  } else if (provenProxy) {
    const idx = usable.findIndex((t) => t.url && t.url === provenProxy);
    if (idx > 0) {
      const [hit] = usable.splice(idx, 1);
      usable.unshift(hit);
    }
  }
  return usable;
}

const availableTiers = plan;

/**
 * The exit the renderers should use. Chrome can only hold one proxy, so
 * failover happens between renders, not mid-render.
 */
function chromeProxyFor(hostname) {
  const usableTiers = plan(hostname);
  const hostProvenTierName = hostname && provenByHost.get(String(hostname).toLowerCase());
  if (hostProvenTierName) {
    const hit = usableTiers.find((t) => t.name === hostProvenTierName);
    if (hit) return hit.url;
  }
  if (provenProxy) {
    const proven = usableTiers.find((t) => t.url && t.url === provenProxy);
    if (proven) return proven.url;
  }
  const first = usableTiers.find((t) => t.url);
  return first ? first.url : '';
}

function currentProxy() {
  if (provenProxy !== null) return provenProxy;
  const all = tiers();
  return all.length ? all[0].url : '';
}

function exhaustedError(hostname, triedNames) {
  const names = Array.from(triedNames || []);
  const e = new Error(
    `All egress tiers refused ${hostname} (tried: ${names.join(', ')}); target server is dropping connections or rate limiting; not retrying for ${Math.round(COOLDOWN_MS / 1000)}s.`
  );
  e.code = 'ERR_EGRESS_ALL_TIERS_OPEN';
  return e;
}

function describe(hostname) {
  return tiers().map((t) => ({ name: t.name, url: t.url, open: Boolean(isOpen(hostname, t.name)) }));
}

function reset() {
  fails.clear();
  provenProxy = null;
  provenByHost.clear();
}

module.exports = {
  tiers,
  plan,
  availableTiers,
  chromeProxyFor,
  currentProxy,
  isTierFailure,
  isNetError: isTierFailure,
  isOpen,
  tripped,
  noteFailure,
  noteSuccess,
  exhaustedError,
  describe,
  reset,
  FAILS_BEFORE_OPEN,
  COOLDOWN_MS,
};
