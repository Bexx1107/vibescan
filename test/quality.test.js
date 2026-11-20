'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { checkQuality } = require('../lib/scanner');

test('checkQuality produces a11y-alt finding with image src evidence', () => {
  const html = `
    <html>
      <body>
        <img src="/static/logo.png">
        <img src='https://cdn.example.com/banner.jpg'>
        <img src="/decorative.svg" alt="">
      </body>
    </html>
  `;
  const findings = [];
  checkQuality(html, { headers: { 'content-encoding': 'gzip', 'cache-control': 'max-age=3600' } }, findings, {});

  const a11yAlt = findings.find((f) => f.id === 'a11y-alt');
  assert.ok(a11yAlt, 'expected a11y-alt finding');
  assert.strictEqual(a11yAlt.severity, 'medium');
  assert.strictEqual(a11yAlt.title, '2 image(s) without alt text');
  assert.strictEqual(a11yAlt.evidence, '/static/logo.png\nhttps://cdn.example.com/banner.jpg');
});

test('checkQuality produces img-format finding with image src evidence', () => {
  const html = `
    <html>
      <body>
        <img src="/assets/hero.png" alt="Hero">
        <img src="/assets/photo.jpg" alt="Photo">
        <img src="/assets/icon.gif" alt="Icon">
        <img src="/assets/modern.webp" alt="Modern">
      </body>
    </html>
  `;
  const findings = [];
  checkQuality(html, { headers: { 'content-encoding': 'gzip', 'cache-control': 'max-age=3600' } }, findings, {});

  const imgFormat = findings.find((f) => f.id === 'img-format');
  assert.ok(imgFormat, 'expected img-format finding');
  assert.strictEqual(imgFormat.severity, 'low');
  assert.strictEqual(imgFormat.title, '3 images served as PNG/JPEG/GIF');
  assert.strictEqual(imgFormat.evidence, '/assets/hero.png\n/assets/photo.jpg\n/assets/icon.gif');
});

test('checkQuality ignores async, defer, nomodule, and type="module" scripts', () => {
  const html = `
    <html>
      <head>
        <script src="/_next/static/chunks/app.js" async=""></script>
        <script src="/_next/static/chunks/vendor.js" async></script>
        <script src="/scripts/bundle.js" defer></script>
        <script src="/_next/static/chunks/legacy.js" noModule=""></script>
        <script src="/scripts/module.js" type="module"></script>
      </head>
      <body></body>
    </html>
  `;
  const findings = [];
  checkQuality(html, { headers: { 'content-encoding': 'gzip', 'cache-control': 'max-age=3600' } }, findings, {});

  const renderBlocking = findings.find((f) => f.id === 'render-blocking');
  assert.strictEqual(renderBlocking, undefined, 'expected no render-blocking finding for async/defer/nomodule/module scripts');
});

test('checkQuality skips render-blocking on post-hydration rendered DOM', () => {
  const dom = `
    <html>
      <head>
        <script src="/_next/static/chunks/chunk1.js"></script>
        <script src="/_next/static/chunks/chunk2.js"></script>
        <script src="/_next/static/chunks/chunk3.js"></script>
      </head>
      <body></body>
    </html>
  `;
  const findings = [];
  checkQuality(dom, { headers: { 'content-encoding': 'gzip', 'cache-control': 'max-age=3600' } }, findings, { isRenderedDom: true });

  const renderBlocking = findings.find((f) => f.id === 'render-blocking');
  assert.strictEqual(renderBlocking, undefined, 'expected no render-blocking finding on rendered DOM');
});

