'use strict';
/**
 * SSRF validation & IP address helpers for VibeScan.
 *
 * Every outbound scanner target and HTTP redirect hop is validated against
 * private, loopback, link-local, carrier-grade NAT, documentation, and
 * embedded IPv6 transition ranges before connecting.
 */

const dns = require('dns').promises;
const net = require('net');

/**
 * Internal non-serializable Symbol allowing opt-in loopback (`127.0.0.1` / `::1`)
 * requests exclusively within in-process automated integration tests.
 * JSON/HTTP payloads and worker IPC messages cannot forge a JS Symbol.
 */
const ALLOW_LOOPBACK_TEST = Symbol('vibescan.allowLoopbackForTest');

function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
}

function isPrivateIPv4(ip) {
  const n = ipToInt(ip);
  const ranges = [
    ['10.0.0.0', 8],
    ['172.16.0.0', 12],
    ['192.168.0.0', 16],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['0.0.0.0', 8],
    ['100.64.0.0', 10],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
  ];
  return ranges.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (n & mask) === (ipToInt(base) & mask);
  });
}

/**
 * Parse an IPv6 literal into its 16 raw bytes, or null if it is not one.
 *
 * Handles "::" compression and an embedded IPv4 tail written either in dotted
 * form (::ffff:127.0.0.1) or as hex hextets (::ffff:7f00:1). A purely textual
 * check (e.g. startsWith('fe80')) is not enough: the same loopback/private
 * address has many equivalent spellings, and every unrecognised one slipped
 * straight through the SSRF guard.
 */
function parseIPv6Bytes(ip) {
  let s = String(ip).trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (!s.includes(':')) return null;

  // Fold an embedded dotted-quad (::ffff:127.0.0.1) into two hex hextets.
  if (s.includes('.')) {
    const m = s.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (!m) return null;
    const o = m[1].split('.').map((n) => parseInt(n, 10));
    if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    s = s.slice(0, m.index) + (((o[0] << 8) | o[1]).toString(16)) + ':' + (((o[2] << 8) | o[3]).toString(16));
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];
  if (halves.length === 1 && head.length !== 8) return null;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 && fill < 1) return null;
  const groups = halves.length === 2 ? [...head, ...new Array(fill).fill('0'), ...tail] : head;
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(groups[i])) return null;
    const n = parseInt(groups[i], 16);
    bytes[i * 2] = n >> 8;
    bytes[i * 2 + 1] = n & 0xff;
  }
  return bytes;
}

function v4FromBytes(b, i) {
  return `${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`;
}

/**
 * True when an IPv6 address is not publicly routable: unspecified, loopback,
 * link-local, site-local, unique-local, multicast, or any form that *embeds* a
 * private/loopback IPv4 — IPv4-mapped (::ffff:0:0/96), IPv4-compatible (::/96),
 * IPv4-translated (::ffff:0:0:0/96), NAT64 (64:ff9b::/96, 64:ff9b:1::/48) and
 * 6to4 (2002::/16).
 *
 * Byte-based, so every textual encoding of the same address is covered. The
 * previous prefix-string check let `::ffff:7f00:1` (loopback) and
 * `::ffff:a9fe:a9fe` (169.254.169.254 cloud metadata) through the guard.
 */
function isPrivateIPv6(ip) {
  const b = parseIPv6Bytes(ip);
  if (!b) return false; // not a valid IPv6 literal; nothing to classify here
  const zeros = (n) => b.slice(0, n).every((x) => x === 0);

  if (zeros(15) && (b[15] === 0 || b[15] === 1)) return true;      // ::  and  ::1
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;       // link-local fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true;       // site-local fec0::/10
  if ((b[0] & 0xfe) === 0xfc) return true;                        // unique-local fc00::/7
  if (b[0] === 0xff) return true;                                 // multicast ff00::/8

  if (zeros(10) && b[10] === 0xff && b[11] === 0xff) {            // IPv4-mapped ::ffff:0:0/96
    return isPrivateIPv4(v4FromBytes(b, 12));
  }
  if (zeros(8) && b[8] === 0xff && b[9] === 0xff) {               // IPv4-translated ::ffff:0:0:0/96
    return isPrivateIPv4(v4FromBytes(b, 12));
  }
  if (zeros(12)) {                                                // IPv4-compatible ::/96
    return isPrivateIPv4(v4FromBytes(b, 12));
  }
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) { // NAT64
    if (b[4] === 0x00 && b[5] === 0x01) return true;             // local-use 64:ff9b:1::/48
    if (b.slice(4, 12).every((x) => x === 0)) {                  // well-known 64:ff9b::/96
      return isPrivateIPv4(v4FromBytes(b, 12));
    }
  }
  if (b[0] === 0x20 && b[1] === 0x02) return isPrivateIPv4(v4FromBytes(b, 2)); // 6to4 2002::/16
  return false;
}

/**
 * Exact host-loopback predicate used ONLY when `ALLOW_LOOPBACK_TEST` is supplied
 * by in-process integration tests (`127.0.0.1` or `::1`, never arbitrary private LAN IPs).
 */
function isLoopbackAddress(ip) {
  const s = String(ip || '').trim();
  const host = (s.startsWith('[') && s.endsWith(']')) ? s.slice(1, -1) : s;
  if (host === '127.0.0.1') return true;
  const b = parseIPv6Bytes(host);
  if (!b) return false;
  return b.slice(0, 15).every((x) => x === 0) && b[15] === 1;
}

/**
 * Resolve a hostname and guarantee it points only at public addresses.
 * Returns { primary, addresses } so the caller can pin the connection to a
 * validated IP (defeats DNS-rebinding between the check and the request).
 */
async function assertPublicHost(hostname, opts = null) {
  const allowLoopback = Boolean(opts && opts[ALLOW_LOOPBACK_TEST] === true);
  // URL.hostname keeps the square brackets on IPv6 literals (e.g. "[::1]"),
  // and net.isIP() returns 0 for that form — so without stripping them an IPv6
  // literal fell through to a doomed DNS lookup instead of being classified.
  const host = (typeof hostname === 'string' && hostname.startsWith('[') && hostname.endsWith(']'))
    ? hostname.slice(1, -1)
    : hostname;

  if (net.isIP(host)) {
    if (allowLoopback && isLoopbackAddress(host)) {
      return { primary: host, addresses: [host], isIP: true };
    }
    if (net.isIPv4(host) && isPrivateIPv4(host)) {
      throw new Error('SSRF blocked: target resolves to a private IPv4 address');
    }
    if (net.isIPv6(host) && isPrivateIPv6(host)) {
      throw new Error('SSRF blocked: target resolves to a private IPv6 address');
    }
    return { primary: host, addresses: [host], isIP: true };
  }
  const addrs = await dns.lookup(host, { all: true }).catch(() => []);
  if (!addrs.length) throw new Error(`DNS resolution failed for ${hostname}`);
  for (const a of addrs) {
    if (a.family === 4 && isPrivateIPv4(a.address)) {
      throw new Error('SSRF blocked: target resolves to a private address');
    }
    if (a.family === 6 && isPrivateIPv6(a.address)) {
      throw new Error('SSRF blocked: target resolves to a private address');
    }
  }
  return { primary: addrs[0].address, addresses: addrs.map((a) => a.address), isIP: false };
}

module.exports = {
  ALLOW_LOOPBACK_TEST,
  ipToInt,
  isPrivateIPv4,
  parseIPv6Bytes,
  v4FromBytes,
  isPrivateIPv6,
  isLoopbackAddress,
  assertPublicHost,
};
