'use strict';
/**
 * Phase 3 — Core Web Vitals measurement over the Chrome DevTools Protocol.
 *
 * Zero external dependencies: talks raw CDP over Node's global WebSocket
 * (Node >= 22). Measures *lab* field-proxy metrics:
 *
 *   - LCP  (largest-contentful-paint)
 *   - CLS  (layout-shift, excluding recent input)
 *   - TBT  (total blocking time from longtasks)  → lab proxy for INP
 *   - TTFB / FCP / DCL / load
 *   - transfer bytes + third-party host map
 *
 * It also returns the post-JS DOM (for the a11y pass) and a computed-style
 * colour-contrast audit (WCAG 1.4.3 / 1.4.11).
 *
 * Everything is best-effort: if Chrome is missing or CDP misbehaves the
 * caller gets { ok:false } and the scan continues.
 */

const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const deep = require('./deep');
const egress = require('./egress');        // follows whichever tier the HTTP layer proved working

/* ------------------------------------------------------------------ *
 * Minimal CDP client (flattened sessions)
 * ------------------------------------------------------------------ */

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.nextId = 1;
    this.pending = new Map();
    this.handlers = [];
    this.ready = new Promise((resolve, reject) => {
      this.ws.onopen = () => resolve();
      this.ws.onerror = (e) => reject(new Error('CDP socket error'));
    });
    this.ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message || 'CDP error'));
        else resolve(msg.result);
      } else if (msg.method) {
        for (const h of this.handlers) { try { h(msg); } catch (e) { /* ignore */ } }
      }
    };
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      const t = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error('CDP timeout: ' + method));
        }
      }, 20000);
      t.unref && t.unref();
      this.ws.send(JSON.stringify(payload), (err) => { if (err) reject(err); });
    });
  }

  on(fn) { this.handlers.push(fn); }

  close() {
    try { this.ws.close(); } catch (e) { /* ignore */ }
  }
}

/* ------------------------------------------------------------------ *
 * Injected page-side observers
 * ------------------------------------------------------------------ */

const BOOTSTRAP = `
try { delete Object.getPrototypeOf(navigator).webdriver; } catch (e) {}
try { Object.defineProperty(navigator, 'webdriver', { get: () => undefined }); } catch (e) {}
try {
  window.chrome = {
    runtime: {},
    loadTimes: function() {},
    csi: function() {},
    app: {}
  };
} catch (e) {}
try {
  Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
  Object.defineProperty(navigator, 'languages', { get: () => ['sl-SI', 'sl', 'en-US', 'en'] });
} catch (e) {}
window.__vs = window.__vs || { lcp: 0, cls: 0, tbt: 0, longTasks: 0, inp: 0, measured: {} };
// Track whether each observer actually registered. This is what lets us tell a
// *legitimately perfect* CLS/TBT of 0 apart from a metric that was never
// measured — the old code treated any 0 as "n/a", so a flawless layout or a
// zero-blocking page was reported as "not measured" instead of "good".
try {
  new PerformanceObserver(function (l) {
    for (const e of l.getEntries()) { if (e.startTime > window.__vs.lcp) window.__vs.lcp = e.startTime; }
  }).observe({ type: 'largest-contentful-paint', buffered: true });
  window.__vs.measured.lcp = true;
} catch (e) {}
try {
  new PerformanceObserver(function (l) {
    for (const e of l.getEntries()) { if (!e.hadRecentInput) window.__vs.cls += e.value; }
  }).observe({ type: 'layout-shift', buffered: true });
  window.__vs.measured.cls = true;
} catch (e) {}
try {
  new PerformanceObserver(function (l) {
    for (const e of l.getEntries()) {
      if (e.duration > 50) { window.__vs.tbt += e.duration - 50; window.__vs.longTasks++; }
    }
  }).observe({ type: 'longtask', buffered: true });
  window.__vs.measured.tbt = true;
} catch (e) {}
try {
  new PerformanceObserver(function (l) {
    for (const e of l.getEntries()) { window.__vs.inp = Math.max(window.__vs.inp, e.duration || 0); }
  }).observe({ type: 'event', buffered: true, durationThreshold: 16 });
} catch (e) {}
`;

// Runs after the settle window. Returns metric JSON as a string.
const METRICS_JS = `
(function () {
  var nav = (performance.getEntriesByType('navigation') || [])[0] || {};
  var res = performance.getEntriesByType('resource') || [];
  var bytes = 0; var hosts = {};
  for (var i = 0; i < res.length; i++) {
    var r = res[i];
    bytes += (r.transferSize || 0);
    try { var h = new URL(r.name).host; hosts[h] = (hosts[h] || 0) + 1; } catch (e) {}
  }
  var fcpEntry = (performance.getEntriesByName('first-contentful-paint') || [])[0] || {};
  var vs = window.__vs || {};
  return JSON.stringify({
    lcp: vs.lcp || 0,
    cls: vs.cls || 0,
    tbt: vs.tbt || 0,
    longTasks: vs.longTasks || 0,
    inp: vs.inp || 0,
    measured: vs.measured || {},
    ttfb: nav.responseStart ? (nav.responseStart - (nav.startTime || 0)) : 0,
    fcp: fcpEntry.startTime || 0,
    dcl: nav.domContentLoadedEventEnd || 0,
    load: nav.loadEventEnd || 0,
    transferBytes: bytes,
    requests: res.length,
    hosts: hosts
  });
})()
`;

const CONTRAST_JS = `
(function () {
  function parse(c) {
    var m = c && c.match(/rgba?\\(([^)]+)\\)/);
    if (!m) return null;
    var p = m[1].split(',').map(function (x) { return parseFloat(x); });
    return { r: p[0], g: p[1], b: p[2], a: p[3] === undefined ? 1 : p[3] };
  }
  function lum(c) {
    function f(x) { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); }
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  }
  function ratio(a, b) {
    var L1 = lum(a), L2 = lum(b);
    return (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
  }
  // Build a short, human-readable CSS path for a node so the report can say
  // *exactly where* a problem is (e.g. "section.plans > span.price"). Prefers a
  // stable #id, falls back to tag + up to two classes, and disambiguates
  // same-tag siblings with :nth-of-type(). Capped at 5 ancestors.
  function cssPath(el) {
    var parts = [];
    var n = el;
    while (n && n.nodeType === 1 && parts.length < 5) {
      var sel = n.nodeName.toLowerCase();
      if (n.id && /^[A-Za-z][\\w-]*$/.test(n.id)) { parts.unshift('#' + n.id); break; }
      var cls = (n.getAttribute('class') || '').trim().split(/\\s+/).filter(Boolean).slice(0, 2);
      if (cls.length) sel += '.' + cls.join('.');
      var p = n.parentElement;
      if (p) {
        var sibs = Array.prototype.filter.call(p.children, function (c) { return c.nodeName === n.nodeName; });
        if (sibs.length > 1) sel += ':nth-of-type(' + (sibs.indexOf(n) + 1) + ')';
      }
      parts.unshift(sel);
      n = p;
    }
    return parts.join(' > ');
  }
  function bg(el) {
    var n = el;
    while (n) {
      var c = parse(getComputedStyle(n).backgroundColor);
      if (c && c.a > 0.5) return c;
      n = n.parentElement;
    }
    return { r: 255, g: 255, b: 255, a: 1 };
  }
  var out = []; var checked = 0;
  var els = document.querySelectorAll('p,span,a,li,h1,h2,h3,h4,h5,h6,button,label,td,th');
  for (var i = 0; i < els.length; i++) {
    var el = els[i];
    if (out.length >= 12) break;
    if (el.children.length) continue;
    var t = (el.textContent || '').trim();
    if (t.length < 3) continue;
    var cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || parseFloat(cs.opacity) < 0.1) continue;
    if (cs.textDecorationLine && cs.textDecorationLine.indexOf('line-through') !== -1) continue;
    if (el.closest && el.closest('[aria-hidden="true"], [disabled], del, s, strike, .line-through')) continue;
    var r0 = el.getBoundingClientRect();
    if (r0.width === 0 || r0.height === 0) continue;
    var fg = parse(cs.color);
    if (!fg) continue;
    var size = parseFloat(cs.fontSize) || 16;
    var weight = parseInt(cs.fontWeight, 10) || 400;
    var large = size >= 24 || (size >= 18.66 && weight >= 700);
    var need = large ? 3 : 4.5;
    var b = bg(el);
    var r = ratio(fg, b);
    checked++;
    if (r < need) {
      out.push({
        ratio: Math.round(r * 100) / 100,
        need: need,
        fontSize: size,
        fg: 'rgb(' + Math.round(fg.r) + ',' + Math.round(fg.g) + ',' + Math.round(fg.b) + ')',
        bg: 'rgb(' + Math.round(b.r) + ',' + Math.round(b.g) + ',' + Math.round(b.b) + ')',
        text: t.slice(0, 70),
        selector: cssPath(el),
        html: (el.outerHTML || '').replace(/\\s+/g, ' ').slice(0, 240)
      });
    }
  }
  return JSON.stringify({ checked: checked, violations: out });
})()
`;

/* ------------------------------------------------------------------ *
 * Measurement driver
 * ------------------------------------------------------------------ */

function tmpProfile() {
  return path.join(os.tmpdir(), 'vs-chrome-' + process.pid + '-' + Date.now());
}

/**
 * Launch headless Chrome with remote debugging and return
 * { proc, wsUrl, profile } once the DevTools endpoint is known.
 */
function launchChrome(targetHost, targetIp, timeoutMs, { bypassProxy = false } = {}) {
  const chrome = deep.pickChrome();
  if (!chrome) return Promise.resolve({ error: 'no headless browser found' });

  const profile = tmpProfile();
  try {
    fs.mkdirSync(profile, { recursive: true });
  } catch (e) { /* ignore */ }
  const args = [
    '--headless=new',
    '--disable-blink-features=AutomationControlled',
    '--remote-debugging-port=0',
    '--user-data-dir=' + profile,
    '--no-sandbox',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-dbus',
    '--disable-extensions',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--hide-scrollbars',
    '--window-size=1366,900',
    '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    '--mute-audio',
    'about:blank',
  ];
  const SCANNER_PROXY = egress.chromeProxyFor(targetHost);
  if (SCANNER_PROXY && !bypassProxy) {
    args.push('--proxy-server=' + SCANNER_PROXY);
  } else if (targetIp && /^[0-9.]+$/.test(targetIp) && targetHost) {
    args.push('--host-resolver-rules=MAP ' + targetHost + ' ' + targetIp);
  }

  return new Promise((resolve) => {
    let proc;
    try {
      let writableHome = process.env.HOME || '/tmp';
      try {
        fs.accessSync(writableHome, fs.constants.W_OK);
      } catch (e) {
        writableHome = profile;
      }
      const isSnap = String(chrome).includes('/snap/');
      const effectiveHome = isSnap ? writableHome : profile;
      proc = spawn(chrome, args, {
        stdio: ['ignore', 'ignore', 'pipe'],
        env: {
          ...process.env,
          HOME: effectiveHome,
          XDG_CONFIG_HOME: effectiveHome,
          XDG_CACHE_HOME: effectiveHome,
          DBUS_SESSION_BUS_ADDRESS: 'disabled:',
        },
      });
    } catch (e) {
      return resolve({ error: e.message });
    }

    let settled = false;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ proc, profile, ...payload });
    };

    const timer = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch (e) { /* ignore */ }
      finish({ error: 'chrome debugging endpoint timed out' });
    }, timeoutMs);

    let buf = '';
    proc.stderr.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (m) finish({ wsUrl: m[1] });
    });
    proc.on('error', (e) => finish({ error: e.message }));
    proc.on('exit', () => finish({ error: 'chrome exited before debugging was ready' }));
  });
}

function cleanup(ctx) {
  if (!ctx) return;
  if (ctx.cdp) ctx.cdp.close();
  if (ctx.proc) { try { ctx.proc.kill('SIGKILL'); } catch (e) { /* ignore */ } }
  if (ctx.profile) {
    try { fs.rmSync(ctx.profile, { recursive: true, force: true }); } catch (e) { /* ignore */ }
  }
}

/**
 * Measure one URL.
 * @returns {Promise<{ok:boolean, metrics?:object, contrast?:object, dom?:string, error?:string}>}
 */
async function measure(targetUrl, { resolvedIp = null, timeoutMs = 28000, settleMs = 2600, bypassProxy = false } = {}) {
  let ctx = null;
  try {
    let host = '';
    try { host = new URL(targetUrl).hostname; } catch (e) { /* ignore */ }

    ctx = await launchChrome(host, resolvedIp, timeoutMs, { bypassProxy });
    if (ctx.error) return { ok: false, error: ctx.error };

    const cdp = new CDP(ctx.wsUrl);
    ctx.cdp = cdp;
    await cdp.ready;

    // Create an about:blank target, then attach to it (flattened session).
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    ctx.targetId = targetId;

    // Collect network/console error counts for the quality domain.
    let failedRequests = 0;
    let failedUrls = [];
    let reqUrlById = new Map();
    let responseCodes = [];
    let docStatus = 0;
    let docHeaders = {};
    cdp.on((msg) => {
      if (msg.method === 'Network.requestWillBeSent' && msg.sessionId === sessionId && msg.params && msg.params.request) {
        reqUrlById.set(msg.params.requestId, msg.params.request.url);
      }
      if (msg.method === 'Network.loadingFailed' && msg.sessionId === sessionId && msg.params) {
        // Ignore client-aborted / canceled requests (e.g. Next.js <Link> ?_rsc= prefetches).
        if (msg.params.canceled || msg.params.errorText === 'net::ERR_ABORTED') return;
        failedRequests++;
        const u = reqUrlById.get(msg.params.requestId);
        if (u) failedUrls.push(`${u} (${msg.params.errorText || 'failed'})`);
      }
      if (msg.method === 'Network.responseReceived' && msg.sessionId === sessionId) {
        // Root document navigation (e.g. WAF interstitials or main document)
        if (msg.params.type === 'Document') {
          if (msg.params.response) {
            docStatus = msg.params.response.status || docStatus;
            if (msg.params.response.headers) docHeaders = msg.params.response.headers;
          }
          return;
        }
        responseCodes.push(msg.params.response.status);
      }
    });

    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Network.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: BOOTSTRAP }, sessionId);

    const loaded = new Promise((resolve) => {
      const h = (msg) => { if (msg.method === 'Page.loadEventFired' && msg.sessionId === sessionId) resolve(true); };
      cdp.on(h);
      setTimeout(() => resolve(false), settleMs + 12000);
    });

    await cdp.send('Page.navigate', { url: targetUrl }, sessionId);
    await loaded;
    await new Promise((r) => { const t = setTimeout(r, settleMs); t.unref && t.unref(); });

    const metricsRes = await cdp.send('Runtime.evaluate', { expression: METRICS_JS, returnByValue: true }, sessionId);
    let metrics = {};
    try { metrics = JSON.parse(metricsRes.result.value); } catch (e) { metrics = {}; }

    const contrastRes = await cdp.send('Runtime.evaluate', { expression: CONTRAST_JS, returnByValue: true }, sessionId);
    let contrast = { checked: 0, violations: [] };
    try { contrast = JSON.parse(contrastRes.result.value); } catch (e) { /* ignore */ }

    const domRes = await cdp.send('Runtime.evaluate', { expression: 'document.documentElement.outerHTML', returnByValue: true }, sessionId);
    const dom = typeof domRes.result.value === 'string' ? domRes.result.value : '';

    metrics.docStatus = docStatus || 0;
    metrics.failedRequests = failedRequests;
    metrics.failedUrls = failedUrls.slice(0, 10);
    metrics.errorCodes = responseCodes.filter((c) => c >= 400).slice(0, 20);

    return { ok: true, metrics, contrast, dom, docStatus, docHeaders };
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    cleanup(ctx);
  }
}

module.exports = { measure, launchChrome, cleanup };
