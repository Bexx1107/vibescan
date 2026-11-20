'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FAVICONS_DIR = path.join(__dirname, '../data/favicons');
if (!fs.existsSync(FAVICONS_DIR)) {
  try {
    fs.mkdirSync(FAVICONS_DIR, { recursive: true });
  } catch (e) {
    console.error('[favicon] Failed to create favicons directory:', e.message);
  }
}

const TRANSPARENT_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64'
);

const GOOGLE_GLOBE_SHA = '59bfe9bc385ad69f50793ce4a53397316d7a875a7148a63c16df9b674c6cda64';
const DDG_GLOBE_SHA = 'e5db88ea2322863ca17817b99d60006c625a31cff0dad49cf05d3c6d16a75c17';

function isGenericGlobe(buf) {
  if (!buf || !Buffer.isBuffer(buf) || buf.length === 0) return true;
  if (buf.length === 726) return true;  // Google default globe fallback
  if (buf.length === 1478) return true; // DuckDuckGo default globe fallback
  try {
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    if (hash === GOOGLE_GLOBE_SHA || hash === DDG_GLOBE_SHA) return true;
  } catch {}
  return false;
}

function detectImageMime(buf, defaultMime = 'image/png') {
  if (!buf || buf.length < 4) return defaultMime;
  // PNG: 89 50 4E 47
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return 'image/png';
  // ICO: 00 00 01 00
  if (buf[0] === 0x00 && buf[1] === 0x00 && buf[2] === 0x01 && buf[3] === 0x00) return 'image/x-icon';
  // JPEG: FF D8 FF
  if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'image/jpeg';
  // WEBP: RIFF...WEBP
  if (buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  // SVG: starts with <svg or <?xml
  const str = buf.toString('utf8', 0, Math.min(buf.length, 128)).trim();
  if (str.startsWith('<svg') || str.startsWith('<?xml')) return 'image/svg+xml';
  return defaultMime;
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

function getPublicHost() {
  try {
    const raw = (process.env.PUBLIC_BASE_URL || '').trim();
    if (!raw) return '';
    return new URL(raw).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}

function sanitizeFaviconHost(input) {
  if (!input) return null;
  let h = String(input).trim().toLowerCase();
  h = h.replace(/^[a-z]+:\/\//, '');
  h = h.split('/')[0].split('?')[0].split(':')[0];
  h = h.replace(/[^a-z0-9.-]/g, '');
  if (!h || h.includes('..') || !h.includes('.')) return null;
  return h;
}

async function fetchAndCacheFavicon(rawHost) {
  const safe = sanitizeFaviconHost(rawHost);
  if (!safe) return null;

  const cachedPng = path.join(FAVICONS_DIR, `${safe}.png`);
  if (fs.existsSync(cachedPng)) {
    try {
      const buf = await fs.promises.readFile(cachedPng);
      if (!isGenericGlobe(buf)) {
        return { path: cachedPng, mime: detectImageMime(buf, 'image/png'), buffer: buf };
      }
      // Purge stale generic globe from disk
      await fs.promises.unlink(cachedPng).catch(() => {});
    } catch {}
  }

  // Check other extensions
  for (const ext of ['.ico', '.jpg', '.jpeg', '.svg', '.webp']) {
    const p = path.join(FAVICONS_DIR, `${safe}${ext}`);
    if (fs.existsSync(p)) {
      try {
        const buf = await fs.promises.readFile(p);
        if (!isGenericGlobe(buf)) {
          const mime = detectImageMime(buf, ext === '.ico' ? 'image/x-icon' : ext === '.svg' ? 'image/svg+xml' : 'image/png');
          return { path: p, mime, buffer: buf };
        }
        await fs.promises.unlink(p).catch(() => {});
      } catch {}
    }
  }

  // Overrides
  const selfHost = getPublicHost();
  if (selfHost && safe === selfHost) {
    const localIcon = path.join(__dirname, '../public/apple-touch-icon.png');
    if (fs.existsSync(localIcon)) {
      try {
        const buf = await fs.promises.readFile(localIcon);
        await fs.promises.writeFile(cachedPng, buf).catch(() => {});
        return { path: localIcon, mime: 'image/png', buffer: buf };
      } catch {}
    }
  }

  // 1. DuckDuckGo Icon Service (Fast, extensive coverage including regional domains & subdomains)
  try {
    const ddgUrl = `https://icons.duckduckgo.com/ip3/${encodeURIComponent(safe)}.ico`;
    const resp = await fetch(ddgUrl, { signal: AbortSignal.timeout(3500) });
    if (resp.ok) {
      const buf = Buffer.from(await resp.arrayBuffer());
      if (buf.length > 0 && !isGenericGlobe(buf)) {
        const mime = detectImageMime(buf, 'image/x-icon');
        await fs.promises.writeFile(cachedPng, buf).catch(() => {});
        return { path: cachedPng, mime, buffer: buf };
      }
    }
  } catch {}

  // 2. Google S2 Service
  try {
    const googleUrl = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(safe)}&sz=64`;
    const resp = await fetch(googleUrl, { signal: AbortSignal.timeout(3500) });
    const cType = resp.headers.get('content-type') || '';
    if (resp.ok && cType.includes('image')) {
      const buf = Buffer.from(await resp.arrayBuffer());
      if (buf.length > 0 && !isGenericGlobe(buf)) {
        await fs.promises.writeFile(cachedPng, buf).catch(() => {});
        return { path: cachedPng, mime: detectImageMime(buf, cType), buffer: buf };
      }
    }
  } catch {}

  // 3. HTML <link rel="icon"> scraping
  for (const proto of ['https://', 'http://']) {
    try {
      const r = await fetch(`${proto}${safe}`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        signal: AbortSignal.timeout(4000)
      });
      if (r.ok) {
        const html = await r.text();
        const match = html.match(/<link[^>]+rel=["'](?:shortcut )?(?:icon|apple-touch-icon)["'][^>]+href=["']([^"']+)["']/i) ||
                      html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:shortcut )?(?:icon|apple-touch-icon)["']/i);
        if (match && match[1]) {
          let iconUrl = match[1].trim();
          if (iconUrl.startsWith('//')) iconUrl = 'https:' + iconUrl;
          else if (iconUrl.startsWith('/')) iconUrl = `${proto}${safe}${iconUrl}`;
          else if (!iconUrl.startsWith('http')) iconUrl = `${proto}${safe}/${iconUrl}`;

          const ir = await fetch(iconUrl, { signal: AbortSignal.timeout(3000) });
          const iType = ir.headers.get('content-type') || '';
          if (ir.ok && (iType.includes('image') || iconUrl.endsWith('.ico') || iconUrl.endsWith('.svg') || iconUrl.endsWith('.png'))) {
            const buf = Buffer.from(await ir.arrayBuffer());
            if (buf.length > 0 && !isGenericGlobe(buf)) {
              const mime = detectImageMime(buf, iType || 'image/png');
              await fs.promises.writeFile(cachedPng, buf).catch(() => {});
              return { path: cachedPng, mime, buffer: buf };
            }
          }
        }
      }
    } catch {}
  }

  // 4. Direct common paths
  const commonPaths = [
    '/favicon.ico',
    '/favicon.png',
    '/icon.png',
    '/icon.svg',
    '/apple-touch-icon.png',
    '/apple-icon.png',
    '/assets/icon_512.png',
    '/assets/favicon.png',
    '/favicon.svg'
  ];

  for (const sub of commonPaths) {
    try {
      const directResp = await fetch(`https://${safe}${sub}`, { signal: AbortSignal.timeout(2500) });
      const directType = directResp.headers.get('content-type') || '';
      if (directResp.ok && (directType.includes('image') || sub.endsWith('.ico') || sub.endsWith('.svg') || sub.endsWith('.png'))) {
        const buf = Buffer.from(await directResp.arrayBuffer());
        if (buf.length > 0 && !isGenericGlobe(buf)) {
          const mime = detectImageMime(buf, directType || 'image/png');
          await fs.promises.writeFile(cachedPng, buf).catch(() => {});
          return { path: cachedPng, mime, buffer: buf };
        }
      }
    } catch {}
  }

  // Do NOT write generic fallback globes to disk. Return null so transparent fallback is served.
  return null;
}

async function serveFavicon(req, res, pathname, q) {
  let rawHost = '';
  if (pathname.startsWith('/api/favicon/')) {
    rawHost = safeDecode(pathname.slice('/api/favicon/'.length)) || '';
  } else if (pathname.startsWith('/api/leaderboard/favicon/')) {
    rawHost = safeDecode(pathname.slice('/api/leaderboard/favicon/'.length)) || '';
  } else if (q && typeof q.get === 'function' && q.get('host')) {
    rawHost = q.get('host');
  }

  const safe = sanitizeFaviconHost(rawHost);
  if (!safe) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Invalid host' }));
  }

  // Self-override: always serve the local high-res app icon for the configured public host
  const selfHost = getPublicHost();
  if (selfHost && safe === selfHost) {
    const localIcon = path.join(__dirname, '../public/apple-touch-icon.png');
    if (fs.existsSync(localIcon)) {
      try {
        const data = await fs.promises.readFile(localIcon);
        res.writeHead(200, {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=604800, immutable',
        });
        return res.end(data);
      } catch {}
    }
  }

  // Fast disk path
  const cachedPng = path.join(FAVICONS_DIR, `${safe}.png`);
  if (fs.existsSync(cachedPng)) {
    try {
      const data = await fs.promises.readFile(cachedPng);
      if (!isGenericGlobe(data)) {
        res.writeHead(200, {
          'Content-Type': detectImageMime(data, 'image/png'),
          'Cache-Control': 'public, max-age=604800, immutable',
        });
        return res.end(data);
      }
      // Purge invalid generic globe from disk
      await fs.promises.unlink(cachedPng).catch(() => {});
    } catch {}
  }

  // Other extensions
  for (const ext of ['.ico', '.jpg', '.jpeg', '.svg', '.webp']) {
    const p = path.join(FAVICONS_DIR, `${safe}${ext}`);
    if (fs.existsSync(p)) {
      try {
        const data = await fs.promises.readFile(p);
        if (!isGenericGlobe(data)) {
          const mime = detectImageMime(data, ext === '.ico' ? 'image/x-icon' : ext === '.svg' ? 'image/svg+xml' : 'image/png');
          res.writeHead(200, {
            'Content-Type': mime,
            'Cache-Control': 'public, max-age=604800, immutable',
          });
          return res.end(data);
        }
        await fs.promises.unlink(p).catch(() => {});
      } catch {}
    }
  }

  // Fetch & cache
  const result = await fetchAndCacheFavicon(safe);
  if (result && result.buffer && !isGenericGlobe(result.buffer)) {
    res.writeHead(200, {
      'Content-Type': result.mime || 'image/png',
      'Cache-Control': 'public, max-age=604800, immutable',
    });
    return res.end(result.buffer);
  }

  // Fallback 1x1 transparent PNG
  res.writeHead(200, {
    'Content-Type': 'image/png',
    'Cache-Control': 'public, max-age=86400',
  });
  return res.end(TRANSPARENT_PNG);
}

module.exports = {
  FAVICONS_DIR,
  TRANSPARENT_PNG,
  isGenericGlobe,
  detectImageMime,
  safeDecode,
  sanitizeFaviconHost,
  fetchAndCacheFavicon,
  serveFavicon,
};
