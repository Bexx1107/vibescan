'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { performance } = require('node:perf_hooks');

const probes = require('../lib/probes');
const { isPublicCompanyTrr } = probes;
const queue = require('../lib/queue');

test('isPublicCompanyTrr resists pathological unclosed script/style ReDoS input in linear time', () => {
  const evilHtml =
    '<script>var x = "' +
    '<'.repeat(50000) +
    '<script' +
    'a<'.repeat(25000) +
    '<footer>Družba d.o.o., TRR SI56 1910 0001 2345 678</footer>';

  const t0 = performance.now();
  const res = isPublicCompanyTrr(evilHtml, '', 'SI56 1910 0001 2345 678');
  const elapsedMs = performance.now() - t0;

  assert.equal(res, true, 'Footer company TRR should still be detected after bounded script/footer scan');
  assert.ok(elapsedMs < 100, `Expected linear runtime < 100ms, got ${elapsedMs.toFixed(1)}ms`);

  const scriptOnlyHtml =
    '<script>const cfg = { iban: "SI56 1910 0001 2345 678", note: "TRR d.o.o." };</script><p>Public landing page</p>';
  assert.equal(
    isPublicCompanyTrr(scriptOnlyHtml, '', 'SI56 1910 0001 2345 678'),
    false,
    'IBAN inside <script> must not be misclassified as visible company footer TRR'
  );
});

test('queue runs concurrent workers, deduplicates in-flight URLs, kills 100%-CPU hung workers with child processes, and enforces MAX_QUEUED', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vibescan-worker-test-'));
  const mockWorkerPath = path.join(tmpDir, 'mock-worker.js');

  fs.writeFileSync(
    mockWorkerPath,
    `'use strict';
const { spawn } = require('child_process');

process.on('message', (msg) => {
  if (!msg || msg.type !== 'run') return;
  const url = String(msg.url || '');

  if (url.includes('hang.example')) {
    const grandchild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 10000)'], {
      stdio: 'ignore',
    });
    try {
      process.send({
        type: 'progress',
        phase: 'hang',
        meta: { workerPid: process.pid, grandchildPid: grandchild.pid },
      });
    } catch (_) {}
    // Allow IPC flush before pegging CPU at 100%
    setTimeout(() => {
      for (;;) {}
    }, 40);
    return;
  }

  if (url.includes('hold.example')) {
    try {
      process.send({ type: 'progress', phase: 'hold', meta: { phaseIdx: 1 } });
    } catch (_) {}
    setInterval(() => {}, 10000);
    return;
  }

  try {
    process.send({ type: 'progress', phase: 'headers', meta: { phaseIdx: 1, msg: 'Mock progress' } });
  } catch (_) {}
  setTimeout(() => {
    const payload = {
      type: 'result',
      report: {
        target: url,
        finalUrl: url + '/',
        score: 95,
        grade: 'A',
        startedAt: new Date().toISOString(),
        domains: {},
        findings: [],
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        meta: {},
      },
    };
    process.send(payload, undefined, undefined, () => process.exit(0));
  }, 250);
});
`
  );

  queue._setWorkerScript(mockWorkerPath);
  t.after(() => {
    queue.shutdown();
    queue._setWorkerScript(null);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const pollUntil = async (fn, timeoutMs = 6000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const val = fn();
      if (val) return val;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error('Timed out waiting for condition');
  };

  // 1. Concurrent workers + in-flight dedup
  const jobA = queue.enqueue('https://fast-a.example', { hideResults: true });
  const jobB = queue.enqueue('https://fast-b.example', { hideResults: true });
  const jobADup = queue.enqueue('https://FAST-A.example/', { hideResults: true });

  assert.equal(jobADup.id, jobA.id, 'Duplicate in-flight URL must attach to active job');

  let maxActive = 0;
  await pollUntil(() => {
    const st = queue.stats();
    if (st.activeWorkers > maxActive) maxActive = st.activeWorkers;
    const a = queue.get(jobA.id);
    const b = queue.get(jobB.id);
    return a && b && a.status === 'done' && b.status === 'done';
  });

  assert.ok(maxActive >= 2, `Expected >= 2 concurrent workers running, observed max ${maxActive}`);
  const doneA = queue.get(jobA.id);
  const reportA = queue.getEphemeralReport(doneA.reportMeta.id);
  assert.ok(reportA, 'Ephemeral report must be stored in parent RAM');
  assert.equal(reportA.score, 95);

  // 2. Hard timeout kills 100%-CPU worker + grandchild process without blocking parent event loop
  const jobHang = queue.enqueue('https://hang.example', { hideResults: true, timeoutMs: 800 });

  let pids = null;
  await pollUntil(() => {
    const cur = queue.get(jobHang.id);
    if (cur && cur.progress && cur.progress.grandchildPid) {
      pids = { workerPid: cur.progress.workerPid, grandchildPid: cur.progress.grandchildPid };
      return pids;
    }
    return null;
  });

  // Confirm parent event loop stays responsive while worker is pegged at 100% CPU
  const hbStart = performance.now();
  await new Promise((r) => setTimeout(r, 20));
  const hbLag = performance.now() - hbStart;
  assert.ok(hbLag < 150, `Parent event loop stayed blocked (${hbLag.toFixed(1)}ms) during CPU-bound worker`);

  const finishedHang = await pollUntil(() => {
    const cur = queue.get(jobHang.id);
    return cur && cur.status === 'error' ? cur : null;
  }, 5000);
  assert.match(finishedHang.error, /timed out/i);

  // Brief yield for OS process reaping
  await new Promise((r) => setTimeout(r, 80));
  const isAlive = (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return e.code !== 'ESRCH';
    }
  };
  assert.equal(isAlive(pids.workerPid), false, 'Hung worker PID must be dead after timeout kill');
  assert.equal(isAlive(pids.grandchildPid), false, 'Spawned grandchild PID must also be dead via process-group SIGKILL');

  // 3. Queue recovers immediately after timeout kill
  const jobAfter = queue.enqueue('https://recovery.example', { hideResults: true });
  const doneAfter = await pollUntil(() => {
    const cur = queue.get(jobAfter.id);
    return cur && cur.status === 'done' ? cur : null;
  });
  assert.equal(doneAfter.status, 'done');

  // 4. Queue cap enforcement
  for (let i = 0; i < queue.CONCURRENCY; i++) {
    queue.enqueue(`https://slot-${i}.hold.example`, { hideResults: true, noDedup: true });
  }
  await pollUntil(() => queue.stats().activeWorkers >= queue.CONCURRENCY);

  for (let i = 0; i < queue.MAX_QUEUED; i++) {
    queue.enqueue(`https://queued-${i}.hold.example`, { hideResults: true, noDedup: true });
  }
  assert.equal(queue.isFull('https://overflow.hold.example'), true);
  assert.throws(
    () => queue.enqueue('https://overflow.hold.example', { hideResults: true, noDedup: true }),
    (err) => err && err.code === 'QUEUE_FULL'
  );

  queue.shutdown();
  assert.equal(queue.stats().activeWorkers, 0);
});

test('active probes invoke rawRequest zero times when opts.skipActive is true', async () => {
  let requestsSent = 0;
  const rawStub = async () => {
    requestsSent += 1;
    return { status: 200, headers: {}, body: '', bytes: 0 };
  };
  const mkStub = (id, severity, title, detail, fix, evidence) => ({ id, severity, title, detail, fix, evidence });
  const findings = [];
  const meta = {};
  const origin = 'https://passive-target.example';
  const html = '<html><head><script src="/app.js"></script></head><body><a href="https://mybucket.s3.amazonaws.com/a.png">img</a></body></html>';
  const jsText = 'fetch("https://storage.googleapis.com/my-bucket-name/file.json");';
  const skipOpts = { skipActive: true };

  await Promise.all([
    probes.checkOpenRedirect(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkReflectedInput(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkHostHeader(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkHttpMethods(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkDirectoryListing(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkCrossdomainPolicy(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkGraphqlIntrospection(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkApiErrorVerbosity(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkOpenBuckets(html, jsText, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkSensitiveFiles(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkSourceMaps(origin, html, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkCorsMisconfiguration(origin, rawStub, findings, meta, mkStub, skipOpts),
    probes.checkAdminDebugEndpoints(origin, rawStub, findings, meta, mkStub, skipOpts),
  ]);

  assert.equal(requestsSent, 0, `Expected 0 outbound requests with skipActive: true, got ${requestsSent}`);
  assert.equal(findings.length, 0);
});
