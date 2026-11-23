/* VibeScan Leaderboard Client
 * Public leaderboard and passive scanner UI.
 * Vanilla JS, no build step, no framework. All copy from i18n.js.
 */

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  };
  const t = (k) => window.i18n.t(k);

  const VIEWS = ['top', 'recent', 'slop', 'creators'];
  const COHORT_VIEWS = new Set(['agency', 'harness', 'model']);

  const state = {
    view: 'top',
    creatorCohort: 'agency',
    scope: 'all', // 'all' (default) or 'si' ("en default pa pol si option")
    searchQuery: '',
    result: null,
    rows: [],
    stats: null,
    activeSite: null,
  };

  /* ---------------- Accessible Hint Tooltips / Toggletips (MWG) ---------------- */

  const ownedHintTriggers = new WeakSet();
  let hintRuntimeInited = false;

  function wireHintTooltips(root = document) {
    if (!root || typeof root.querySelectorAll !== 'function') return;
    root.querySelectorAll('[interestfor]').forEach((trigger) => {
      const targetId = trigger.getAttribute('interestfor');
      if (!targetId) return;
      const tip = document.getElementById(targetId);
      if (!tip || tip.getAttribute('popover') !== 'hint') return;
      if (!tip.hasAttribute('role')) tip.setAttribute('role', 'tooltip');

      const opensOnActivate = trigger.hasAttribute('popovertarget') || trigger.hasAttribute('commandfor');
      if (opensOnActivate && !trigger.hasAttribute('aria-expanded')) {
        trigger.setAttribute('aria-expanded', tip.matches(':popover-open') ? 'true' : 'false');
        ownedHintTriggers.add(trigger);
      } else if (!opensOnActivate && !trigger.hasAttribute('aria-describedby')) {
        trigger.setAttribute('aria-describedby', tip.id);
      }
    });
  }

  function initHintTooltipRuntime() {
    if (hintRuntimeInited) return;
    hintRuntimeInited = true;

    // `toggle` does not bubble — capture on document to sync aria-expanded accurately.
    document.addEventListener(
      'toggle',
      (ev) => {
        const tip = ev.target;
        if (!tip || !tip.id) return;
        const expanded = ev.newState === 'open' ? 'true' : 'false';
        document.querySelectorAll(`[interestfor="${CSS.escape(tip.id)}"]`).forEach((trigger) => {
          if (ownedHintTriggers.has(trigger)) {
            trigger.setAttribute('aria-expanded', expanded);
          }
        });
      },
      true
    );

    // Fallback for browsers where `popover="hint"` defaults to `manual` (e.g. Safari):
    // upgrade active toggletips to `auto` on `beforetoggle` so click/light-dismiss/Esc close them.
    const probe = document.createElement('div');
    probe.popover = 'hint';
    if (probe.popover !== 'hint') {
      document.addEventListener(
        'beforetoggle',
        ({ target, newState }) => {
          if (
            newState === 'open' &&
            target &&
            target.id &&
            target.getAttribute('popover') === 'hint' &&
            document.querySelector(`[popovertarget="${CSS.escape(target.id)}"]`)
          ) {
            target.popover = 'auto';
          }
        },
        true
      );
    }

    wireHintTooltips(document);
  }

  function formatTemplate(tpl, vars) {
    return String(tpl || '').replace(/\{([a-zA-Z0-9_]+)\}/g, (_, k) =>
      vars && vars[k] !== undefined && vars[k] !== null ? String(vars[k]) : ''
    );
  }

  function normalizeDegradedInfo(raw) {
    if (!raw || typeof raw !== 'object') return null;

    // 1. Report shape (`publicReport` or full scanner report)
    if (raw.degraded && typeof raw.degraded === 'object' && raw.degraded.degraded) {
      const d = raw.degraded;
      const caps = Array.isArray(d.capabilities) ? d.capabilities : [];
      const headersOnly =
        caps.includes('waf-headers-unverified') &&
        !caps.includes('waf-intercepted') &&
        !caps.includes('waf-bypass');
      const kind =
        d.kind ||
        (caps.includes('waf-intercepted') || caps.includes('waf-bypass') || headersOnly
          ? 'waf'
          : caps.includes('headless-render')
            ? 'render'
            : 'partial');
      return {
        kind,
        headersOnly,
        scoreCap: typeof d.scoreCap === 'number' ? d.scoreCap : kind === 'waf' ? 70 : 79,
        scoreUncapped: typeof raw.scoreUncapped === 'number' ? raw.scoreUncapped : null,
        reason: d.reason || null,
        hint: d.hint || null,
        unrunChecks: Array.isArray(d.unrunChecks) ? d.unrunChecks : [],
        wafProvider: d.wafProvider || (raw.meta && raw.meta.wafProvider) || null,
      };
    }

    if (raw.meta && raw.meta.degraded && raw.meta.degraded.degraded) {
      return normalizeDegradedInfo({ degraded: raw.meta.degraded, scoreUncapped: raw.scoreUncapped, meta: raw.meta });
    }

    if (Array.isArray(raw.findings) && raw.findings.some((f) => f.id === 'scan-degraded')) {
      const hasWaf = Boolean((raw.meta && raw.meta.isWafChallenge) || raw.findings.some((f) => f.id === 'waf-challenge-intercepted'));
      return {
        kind: hasWaf ? 'waf' : 'partial',
        headersOnly: false,
        scoreCap: hasWaf ? 70 : 79,
        scoreUncapped: typeof raw.scoreUncapped === 'number' ? raw.scoreUncapped : null,
        reason: null,
        hint: null,
        unrunChecks: [],
        wafProvider: (raw.meta && raw.meta.wafProvider) || null,
      };
    }

    // 2. Leaderboard / site-history row shape (`{ degraded: true, degradedReason, scoreCap }`)
    if (raw.degraded) {
      const kind = raw.degradedReason || 'partial';
      const capVal = typeof raw.scoreCap === 'number' ? raw.scoreCap : kind === 'waf' ? 70 : 79;
      return {
        kind,
        headersOnly: false,
        scoreCap: capVal,
        scoreUncapped: null,
        reason: null,
        hint: null,
        unrunChecks: [],
        wafProvider: null,
      };
    }

    return null;
  }

  function buildReliabilityBadge(info, tipId, { showUncapped = false } = {}) {
    if (!info) return null;
    const isSl = window.i18n.lang() === 'sl';
    const capVal = info.scoreCap || (info.kind === 'waf' ? 70 : 79);

    let tplKey = 'degradedPartialBadge';
    let titleKey = 'degradedPartialTitle';
    if (info.kind === 'waf') {
      tplKey = 'degradedWafBadge';
      titleKey = 'degradedWafTitle';
    } else if (info.kind === 'render') {
      tplKey = 'degradedRenderBadge';
      titleKey = 'degradedRenderTitle';
    }

    const label = formatTemplate(t(tplKey), { cap: capVal });
    const wrap = el('span', 'reliability-lockup');

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `reliability-badge-btn kind-${info.kind}`;
    btn.setAttribute('interestfor', tipId);
    btn.setAttribute('popovertarget', tipId);
    btn.setAttribute('popovertargetaction', 'show');
    // WCAG 2.5.3 Label in Name: keep the visible text inside aria-label.
    btn.setAttribute('aria-label', `${label} — ${t('degradedInfoAria')}`);
    btn.innerHTML =
      `<svg class="reliability-icon" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 2.2L14.2 13H1.8L8 2.2z"/><line x1="8" y1="6.4" x2="8" y2="9.6"/><circle cx="8" cy="11.4" r="0.6" fill="currentColor" stroke="none"/></svg>` +
      `<span>${label}</span>`;
    wrap.appendChild(btn);

    if (showUncapped && typeof info.scoreUncapped === 'number') {
      const uncappedText = formatTemplate(t('degradedUncapped'), { score: info.scoreUncapped });
      wrap.appendChild(el('span', 'reliability-uncapped', `(${uncappedText})`));
    }

    // Popover placed immediately after trigger so screen reader browse order flows naturally.
    const tip = el('div', 'reliability-popover');
    tip.id = tipId;
    tip.setAttribute('popover', 'hint');
    tip.setAttribute('role', 'tooltip');

    const popTitle = info.headersOnly
      ? (isSl ? 'Nepopolna analiza — WAF je blokiral izvorne HTTP glave' : 'Partial scan — WAF blocked origin HTTP headers')
      : t(titleKey);
    tip.appendChild(el('div', 'reliability-popover-title', popTitle));
    const defaultDesc = info.headersOnly
      ? (isSl
          ? `Ciljni WAF${info.wafProvider ? ' (' + info.wafProvider + ')' : ''} je blokiral neposredni zajem HTTP glav; vsebina strani je bila pregledana prek nadomestnega zajema, zato varnostne glave niso preverjene in je ocena omejena na ${capVal}.`
          : `Target WAF${info.wafProvider ? ' (' + info.wafProvider + ')' : ''} blocked direct HTTP header capture; page content was analyzed via fallback rendering, so security headers remain unverified and the score is capped at ${capVal}.`)
      : info.kind === 'waf'
        ? (isSl
            ? `Ciljna stran je pregled zavrnila z WAF / bot izzivom${info.wafProvider ? ' (' + info.wafProvider + ')' : ''}. Ocena je začasno omejena na največ ${capVal}, da delni odziv ne deluje kot polno preverjena stran.`
            : `Target returned a WAF / bot challenge${info.wafProvider ? ' (' + info.wafProvider + ')' : ''}. The score is capped at ${capVal} so skipped checks never inflate the grade.`)
        : info.kind === 'render'
          ? (isSl
              ? `Brskalniški izris (Chromium) ni bil na voljo, zato CWV in izrisana dostopnost nista mogla teči. Ocena je omejena na največ ${capVal}.`
              : `Headless browser rendering (Chromium) was unavailable, so lab CWV and rendered accessibility did not run. The score is capped at ${capVal}.`)
          : (isSl
              ? `Del pregledov ni uspel teči. Ocena je omejena na največ ${capVal}.`
              : `One or more verification passes did not complete. The score is capped at ${capVal}.`);
    tip.appendChild(el('p', 'reliability-popover-desc', info.headersOnly ? defaultDesc : (info.reason || defaultDesc)));

    if (typeof info.scoreUncapped === 'number') {
      const capMeta = isSl
        ? `Pred omejitvijo: ${info.scoreUncapped} → omejeno na ${capVal}`
        : `Before cap: ${info.scoreUncapped} → capped at ${capVal}`;
      tip.appendChild(el('div', 'reliability-popover-meta', capMeta));
    }

    if (info.unrunChecks && info.unrunChecks.length) {
      tip.appendChild(
        el('div', 'reliability-popover-meta', `${t('degradedUnrunLabel')} ${info.unrunChecks.join(', ')}`)
      );
    }

    wrap.appendChild(tip);
    return wrap;
  }

  /* ---------------- Theme (Dark Mode Only) ---------------- */

  function initTheme() {
    document.documentElement.setAttribute('data-theme', 'dark');
    try {
      localStorage.setItem('vibescan.theme_v2', 'dark');
      localStorage.removeItem('vibescan.theme');
    } catch (e) {}
  }

  function applyStaticText() {
    document.documentElement.lang = window.i18n.lang();
    document.title = t('title');
    $$('[data-i18n]').forEach((node) => {
      const val = t(node.dataset.i18n);
      if (typeof val === 'string' && val.includes('<br>')) {
        if (node.innerHTML !== val) node.innerHTML = val;
      } else {
        if (node.textContent !== val) node.textContent = val;
      }
    });
    $$('[data-i18n-attr]').forEach((node) => {
      const parts = node.dataset.i18nAttr.split(':');
      if (parts.length === 2) node.setAttribute(parts[0], t(parts[1]));
    });

    $('#langSwitch').textContent = window.i18n.lang() === 'sl' ? 'EN' : 'SL';
    const dLang = $('#drawerLangSwitch');
    if (dLang) dLang.textContent = window.i18n.lang() === 'sl' ? 'English (EN)' : 'Slovenščina (SL)';
    $('#urlInput').placeholder = t('submitPlaceholder');
    $('#langSwitch').setAttribute('aria-label', t('langSwitchAria'));

    updateScopeButtons();
    updateSubrows();
    buildTabs();
    if (state.stats) updateStatsDisplay(state.stats);
    renderBoard();
    if (state.result) renderResult(state.result);
  }

  document.addEventListener('langchange', applyStaticText);
  $('#langSwitch').addEventListener('click', () => window.i18n.toggle());
  const dLangBtn = $('#drawerLangSwitch');
  if (dLangBtn) dLangBtn.addEventListener('click', () => window.i18n.toggle());

  /* ---------------- Scope Control ("en default pa pol si option") ---------------- */

  function initScope() {
    const params = new URLSearchParams(location.search);
    const scopeParam = params.get('scope');
    if (scopeParam === 'si' || scopeParam === 'all') {
      state.scope = scopeParam;
    } else {
      state.scope = 'all';
      localStorage.removeItem('vibescan.scope');
    }

    updateScopeButtons();
    updateSubrows();

    $('#scopeAllBtn')?.addEventListener('click', () => setScope('all'));
    $('#scopeSiBtn')?.addEventListener('click', () => setScope('si'));

    $('#subCohortAgency')?.addEventListener('click', () => {
      state.creatorCohort = 'agency';
      updateSubrows();
      loadBoard();
    });
    $('#subCohortModel')?.addEventListener('click', () => {
      state.creatorCohort = 'model';
      updateSubrows();
      loadBoard();
    });
    $('#subCohortHarness')?.addEventListener('click', () => {
      state.creatorCohort = 'harness';
      updateSubrows();
      loadBoard();
    });
  }

  function setScope(scope) {
    if (state.scope === scope) return;
    state.scope = scope;
    localStorage.setItem('vibescan.scope', scope);
    updateScopeButtons();

    // Update URL query string
    const url = new URL(location);
    if (scope === 'all') url.searchParams.delete('scope');
    else url.searchParams.set('scope', scope);
    history.replaceState(null, '', url);

    loadBoard();
  }

  function updateScopeButtons() {
    const allBtn = $('#scopeAllBtn');
    const siBtn = $('#scopeSiBtn');
    if (allBtn && siBtn) {
      allBtn.classList.toggle('active', state.scope === 'all');
      siBtn.classList.toggle('active', state.scope === 'si');
      const allSpan = allBtn.querySelector('span:first-child');
      if (allSpan) allSpan.textContent = t('scopeAllShort');
      const siSpan = siBtn.querySelector('span:first-child');
      if (siSpan) siSpan.textContent = t('scopeSiShort');
    }
  }

  function updateSubrows() {
    const creatorsSubrow = $('#creatorsSubrow');
    if (!creatorsSubrow) return;

    if (state.view === 'creators') {
      creatorsSubrow.hidden = false;
      const currentCohort = state.creatorCohort || 'agency';
      $('#subCohortAgency')?.classList.toggle('active', currentCohort === 'agency');
      $('#subCohortModel')?.classList.toggle('active', currentCohort === 'model');
      $('#subCohortHarness')?.classList.toggle('active', currentCohort === 'harness');
    } else {
      creatorsSubrow.hidden = true;
    }
  }

  /* ---------------- Tabs ---------------- */

  function buildTabs() {
    const holder = $('#tabs');
    if (!holder) return;
    holder.textContent = '';
    for (const v of VIEWS) {
      const isSlop = v === 'slop';
      const b = el('button', 'tab-btn' + (isSlop ? ' slop' : '') + (v === state.view ? ' active' : ''), t('tabs.' + v));
      b.type = 'button';
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', String(v === state.view));
      b.addEventListener('click', () => {
        state.view = v;
        const url = new URL(location);
        if (v === 'top') {
          url.searchParams.delete('view');
          url.searchParams.delete('cohort');
        } else {
          url.searchParams.set('view', v);
          if (v === 'creators') {
            url.searchParams.set('cohort', state.creatorCohort || 'agency');
          } else {
            url.searchParams.delete('cohort');
          }
        }
        history.replaceState(null, '', url);

        buildTabs();
        updateSubrows();
        loadBoard();
      });
      holder.appendChild(b);
    }
  }

  /* ---------------- Leaderboard Data & Render ---------------- */

  async function loadBoard() {
    const apiView = state.view === 'creators' ? (state.creatorCohort || 'agency') : state.view;
    const q = new URLSearchParams({
      view: apiView,
      scope: state.scope,
      limit: '10',
    });

    try {
      const res = await fetch('/api/leaderboard?' + q.toString());
      if (!res.ok) return;
      const data = await res.json();
      state.rows = data.rows || [];
      state.stats = data.stats || null;
      updateStatsDisplay(data.stats);
      updateSpotlights();
      renderBoard();
    } catch (e) {
      console.error('Failed to load leaderboard', e);
    }
  }

  async function updateSpotlights() {
    try {
      // 1. Fetch top domain for best spotlight
      const topRes = await fetch('/api/leaderboard?view=top&limit=1');
      if (topRes.ok) {
        const topData = await topRes.json();
        const top = (topData.rows && topData.rows[0]) || null;
        if (top) {
          const hostEl = $('#topSpotlightHost');
          const scoreEl = $('#topSpotlightScore');
          const gradeEl = $('#topSpotlightGrade');
          const cardEl = $('#spotlightTopCard');
          if (hostEl) hostEl.textContent = top.host;
          if (scoreEl) scoreEl.textContent = String(top.score);
          if (gradeEl) {
            gradeEl.textContent = top.grade || 'A';
            if (!gradeEl.classList.contains('showcase-ring-grade')) {
              gradeEl.className = 'spotlight-grade-badge grade-' + (top.grade || 'A');
            }
          }
          if (cardEl) {
            cardEl.onclick = () => openSiteDrawer(top.host);
          }
        }
      }

      // 2. Fetch worst domain for slop spotlight
      const slopRes = await fetch('/api/leaderboard?view=slop&limit=1');
      if (slopRes.ok) {
        const slopData = await slopRes.json();
        const slop = (slopData.rows && slopData.rows[0]) || null;
        if (slop) {
          const hostEl = $('#slopSpotlightHost');
          const scoreEl = $('#slopSpotlightScore');
          const gradeEl = $('#slopSpotlightGrade');
          const cardEl = $('#spotlightSlopCard');
          if (hostEl) hostEl.textContent = slop.host;
          if (scoreEl) scoreEl.textContent = String(slop.score);
          if (gradeEl) {
            gradeEl.textContent = slop.grade || 'D';
            gradeEl.className = 'spotlight-grade-badge grade-' + (slop.grade || 'D');
          }
          if (cardEl) {
            cardEl.onclick = () => openSiteDrawer(slop.host);
          }
        }
      }
    } catch (e) {
      console.warn('Spotlights fetch error', e);
    }
  }

  function updateStatsDisplay(stats) {
    if (!stats) return;
    const countAllEl = $('#countAll');
    const countSiEl = $('#countSi');
    const statsLabelEl = $('#statsLabel');
    const heroSitesEl = $('#heroStatSites');
    const heroSiEl = $('#heroStatSi');
    const heroScansEl = $('#heroStatScans');
    const heroVerifiedEl = $('#heroStatVerified');

    const totalSites = stats.sites || 0;
    const siSites = stats.sitesSi || stats.sites_si || 0;
    const totalScans = stats.scans || 0;
    const verifiedCount = stats.verified || 0;

    if (countAllEl) countAllEl.textContent = String(totalSites);
    if (countSiEl) countSiEl.textContent = String(siSites);
    if (statsLabelEl) {
      statsLabelEl.textContent = `${totalSites} domen · ${totalScans} skenov`;
    }
    if (heroSitesEl) heroSitesEl.textContent = String(totalSites);
    if (heroSiEl) heroSiEl.textContent = `${siSites} .si`;
    if (heroScansEl) heroScansEl.textContent = String(totalScans);
    if (heroVerifiedEl) heroVerifiedEl.textContent = `${verifiedCount} ${t('statVerifiedSuffix')}`;
  }

  function renderBoard() {
    $('#boardTitle').textContent = t('tabs.' + state.view);

    let sub = '';
    if (state.view === 'slop') sub = t('wallOfSlopSub');
    else if (state.view === 'creators' || COHORT_VIEWS.has(state.view)) sub = t('smallSampleHelp');

    $('#boardSub').textContent = sub;

    // Filter rows client-side if search query is active
    let displayRows = state.rows;
    if (state.searchQuery.trim()) {
      const query = state.searchQuery.toLowerCase().trim();
      displayRows = state.rows.filter((r) => {
        const hostMatch = (r.host || '').toLowerCase().includes(query);
        const nameMatch = (r.claim && r.claim.builderName || '').toLowerCase().includes(query);
        const toolMatch = (r.claim && (r.claim.harness || r.claim.model || '')).toLowerCase().includes(query);
        const labelMatch = (r.label || '').toLowerCase().includes(query);
        return hostMatch || nameMatch || toolMatch || labelMatch;
      });
    }

    const counter = $('#boardCount');
    if (counter) {
      const countLabel = state.view === 'creators' ? t('tabs.creators').toLowerCase() : t('colSite').toLowerCase();
      counter.textContent = `${displayRows.length} ${countLabel}`;
    }

    const body = $('#rows');
    body.textContent = '';

    if (!displayRows.length) {
      const emptyDiv = el('div', 'floating-site-card empty-card');
      emptyDiv.appendChild(el('span', 'empty-text', state.view === 'slop' ? t('emptySlop') : t('empty')));
      body.appendChild(emptyDiv);
      return;
    }

    const isCohort = state.view === 'creators' || COHORT_VIEWS.has(state.view);
    if (isCohort) {
      displayRows.forEach((r, i) => body.appendChild(cohortRow(r, i + 1)));
    } else {
      displayRows.forEach((r, i) => body.appendChild(siteRow(r, i + 1)));
    }
    wireHintTooltips(body);
  }

  function siteRow(r, rank) {
    const card = el('div', 'floating-site-card rank-' + rank);
    card.dataset.host = r.host;

    const mainRow = el('div', 'card-main-row');

    // Card Left: Favicon Badge + Domain & Builder Meta
    const lead = el('div', 'card-lead');

    // Favicon Badge (replaces rank numbers with real website favicons)
    const faviconBadge = el('div', 'card-favicon-badge');
    const faviconImg = el('img', 'card-favicon-img');
    faviconImg.alt = r.host;
    faviconImg.width = 24;
    faviconImg.height = 24;
    faviconImg.loading = 'lazy';
    faviconImg.src = `/api/favicon/${encodeURIComponent(r.host)}?v=4`;
    faviconImg.onerror = function() {
      if (!this.dataset.fallback) {
        this.dataset.fallback = '1';
        this.src = `https://icons.duckduckgo.com/ip3/${encodeURIComponent(r.host)}.ico`;
      } else if (this.dataset.fallback === '1') {
        this.dataset.fallback = '2';
        this.src = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(r.host)}&sz=64`;
      }
    };
    faviconBadge.appendChild(faviconImg);
    lead.appendChild(faviconBadge);

    // Meta: Domain Name + Made by attribution
    const meta = el('div', 'card-meta');
    const hostEl = el('span', 'card-host-title', r.host);
    meta.appendChild(hostEl);

    // Builder line (Made by: ...)
    const builderLine = el('div', 'card-builder-line');
    if (r.claim && (r.claim.builderName || r.claim.builderKind || r.claim.platform || r.claim.harness || r.claim.model)) {
      const prefix = el('span', 'builder-prefix', (t('madeByPrefix') || 'Made by:') + ' ');
      builderLine.appendChild(prefix);

      let builderName = r.claim.builderName;
      if (!builderName && r.claim.builderKind && r.claim.builderKind !== 'unknown') {
        builderName = t('kind' + cap(r.claim.builderKind));
      }
      if (builderName) {
        builderLine.appendChild(el('strong', 'builder-name', builderName));
      }

      // Add extra framework / harness tag if present (e.g. Next.js, Cursor)
      const extra = [];
      if (r.claim.platform && r.claim.platform !== 'unknown' && r.claim.platform !== 'custom') {
        extra.push(r.claim.platform);
      }
      if (r.claim.harness) extra.push(r.claim.harness);
      if (extra.length > 0) {
        builderLine.appendChild(el('span', 'builder-extra', ' (' + extra[0] + ')'));
      }
    } else {
      builderLine.appendChild(el('span', 'builder-unclaimed', t('unclaimedSite') || 'Brez prijavljenega avtorja'));
    }
    meta.appendChild(builderLine);
    lead.appendChild(meta);
    mainRow.appendChild(lead);

    // Desktop-only middle badges (Tech stack, AI harness/model, Verification status)
    if (r.claim) {
      const desktopBadges = el('div', 'card-desktop-badges desktop-only');
      if (r.claim.harness) {
        desktopBadges.appendChild(el('span', 'desktop-meta-pill pill-agent', r.claim.harness));
      }
      if (r.claim.model) {
        desktopBadges.appendChild(el('span', 'desktop-meta-pill pill-model', r.claim.model));
      }
      if (r.claim.platform && r.claim.platform !== 'unknown') {
        desktopBadges.appendChild(el('span', 'desktop-meta-pill pill-stack', r.claim.platform));
      }
      if (r.claim.verification === 'verified') {
        desktopBadges.appendChild(el('span', 'desktop-meta-pill pill-verified', '✓ Verified'));
      }
      mainRow.appendChild(desktopBadges);
    }

    // Card Right: Score Number + Reliability Badge + Grade Badge Pill
    const tail = el('div', 'card-tail');

    const degInfo = normalizeDegradedInfo(r);
    if (degInfo) {
      const safeId = String(r.id || rank).replace(/[^A-Za-z0-9_-]/g, '');
      const relNode = buildReliabilityBadge(degInfo, `tip-board-${safeId}-${rank}`);
      if (relNode) tail.appendChild(relNode);
    }

    tail.appendChild(el('span', 'card-score-value', String(r.score)));

    let rawGrade = (r.grade || 'C').toUpperCase();
    if (rawGrade === 'A' && r.score >= 97) rawGrade = 'A+';
    const gradeLetter = rawGrade.charAt(0).toLowerCase();
    const gradeBadge = el('span', 'card-grade-badge grade-' + gradeLetter, rawGrade);
    tail.appendChild(gradeBadge);
    mainRow.appendChild(tail);

    card.appendChild(mainRow);

    // Inline expandable panel: Ocene po področjih (6 domain scores)
    const expandPanel = el('div', 'card-expand-panel');
    const expandInner = el('div', 'card-expand-inner');
    const expandTitle = el(
      'div',
      'card-expand-title',
      t('domainScores') || (window.i18n && window.i18n.lang() === 'en' ? 'Domain Scores' : 'Ocene po področjih')
    );
    expandInner.appendChild(expandTitle);

    const grid = el('div', 'card-domain-grid');
    const domainKeys = ['sec', 'comp', 'perf', 'a11y', 'seo', 'quality'];
    const domainKeyMap = {
      sec: 'security',
      comp: 'compliance',
      perf: 'performance',
      a11y: 'accessibility',
      seo: 'seo',
      quality: 'quality',
    };

    domainKeys.forEach((k) => {
      const val = r[k];
      if (val === undefined || val === null) return;
      const item = el('div', 'card-domain-item');
      const dMeta = el('div', 'card-domain-meta');
      dMeta.appendChild(el('span', 'card-domain-name', getDomainLabel(domainKeyMap[k] || k)));
      dMeta.appendChild(el('span', 'card-domain-score', String(val)));
      item.appendChild(dMeta);

      const track = el('div', 'card-domain-track');
      const fill = el('div', 'card-domain-fill' + (val < 55 ? ' low' : val < 75 ? ' medium' : ''));
      fill.style.width = Math.max(0, Math.min(100, val)) + '%';
      track.appendChild(fill);
      item.appendChild(track);
      grid.appendChild(item);
    });

    expandInner.appendChild(grid);
    expandPanel.appendChild(expandInner);
    card.appendChild(expandPanel);

    if (state.activeSite === r.host) {
      card.classList.add('expanded');
    }

    // Click handler to toggle inline expansion (ignore clicks on interactive badge/popover controls)
    card.addEventListener('click', (e) => {
      if (e.target.closest('.reliability-badge-btn, .reliability-popover')) return;
      e.preventDefault();
      const wasExpanded = card.classList.contains('expanded');
      $$('.floating-site-card.expanded').forEach((c) => c.classList.remove('expanded'));
      if (!wasExpanded) {
        card.classList.add('expanded');
        state.activeSite = r.host;
      } else {
        state.activeSite = null;
      }
    });

    return card;
  }

  function cohortRow(r, rank) {
    const card = el('div', 'floating-site-card cohort-card rank-' + rank);
    const lead = el('div', 'card-lead');
    lead.appendChild(el('div', 'card-rank-pill pill-neutral', '#' + String(rank).padStart(2, '0')));

    const meta = el('div', 'card-meta');
    meta.appendChild(el('span', 'card-host-title', r.label));
    lead.appendChild(meta);
    card.appendChild(lead);

    const tail = el('div', 'card-tail');
    const scoreVal = r.eligible ? Number(r.avg_score).toFixed(1) : (r.min_score === r.max_score ? String(r.min_score) : `${r.min_score}–${r.max_score}`);
    tail.appendChild(el('span', 'card-score-value', scoreVal));
    card.appendChild(tail);
    return card;
  }

  function claimCell(claim) {
    const wrap = el('div', 'claim-cell-wrap');
    if (!claim) {
      wrap.innerHTML = window.BRAND_ICONS
        ? window.BRAND_ICONS.renderClaimBadge(null)
        : '<span class="badge-status empty">Brez trditve</span>';
      return wrap;
    }

    // Top status verification indicator (if verified or contradicted)
    if (claim.verification && claim.verification !== 'unverified') {
      const badgeRow = el('div', 'claim-badge-row');
      const statusBadge = el('span', 'badge-status ' + claim.verification, t(claim.verification));
      statusBadge.title = t(claim.verification + 'Help');
      badgeRow.appendChild(statusBadge);
      wrap.appendChild(badgeRow);
    }

    if (window.BRAND_ICONS) {
      const cluster = document.createElement('div');
      cluster.innerHTML = window.BRAND_ICONS.renderClaimBadge(claim);
      wrap.appendChild(cluster.firstElementChild || cluster);
    } else {
      const label = claim.builderName || (claim.builderKind ? t('kind' + cap(claim.builderKind)) : '');
      if (label) wrap.appendChild(el('div', 'claim-title', label));
      const tools = [claim.harness, claim.model].filter(Boolean).join(' / ');
      if (tools) wrap.appendChild(el('div', 'claim-tools-text', tools));
    }

    return wrap;
  }

  function cap(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
  }

  function formatScanError(msg) {
    const raw = String(msg || '');
    const isSl = window.i18n.lang() === 'sl';
    if (/all egress tiers refused|err_egress_all_tiers_open|dropping connections|rate limiting/i.test(raw)) {
      return isSl
        ? 'Ciljni strežnik se ne odziva (strežnik ali njegov ponudnik gostovanja, npr. Netlify/Cloudflare, začasno zavrača ali omejuje povezave zaradi Rate Limita ali DDoS zaščite). Poskusite znova čez nekaj minut.'
        : 'Target server is not responding (host or CDN provider like Netlify/Cloudflare is temporarily dropping connections or rate limiting). Please retry in a few minutes.';
    }
    if (/client network socket disconnected|connection reset|econnreset/i.test(raw)) {
      return isSl
        ? 'Ciljni strežnik je prekinil povezavo med vzpostavljanjem TLS kanala (strežnik morda blokira VPN/tuje IP naslove ali zavrača povezave).'
        : 'Target host rejected connection during TLS handshake (remote server may be blocking VPN/datacenter IP ranges or terminating connections).';
    }
    if (/econnrefused/i.test(raw)) {
      return isSl
        ? 'Povezava zavrnjena: na ciljnem naslovu ne teče noben spletni strežnik.'
        : 'Connection refused: no web server is listening on the target address.';
    }
    if (/enotfound|getaddrinfo/i.test(raw)) {
      return isSl
        ? 'Domena ne obstaja ali je ni mogoče razrešiti v DNS sistemu.'
        : 'Domain does not exist or could not be resolved via DNS.';
    }
    if (/etimedout|timeout/i.test(raw)) {
      return isSl
        ? 'Časovna omejitev potekla: ciljni strežnik se ni pravočasno odzval.'
        : 'Connection timed out: target server took too long to respond.';
    }
    return raw || (isSl ? 'Analiza spletnega mesta ni uspela.' : 'Audit failed.');
  }

  /* ---------------- Scan Submission ---------------- */

  const SCAN_PHASES = [
    'scanningStep1',
    'scanningStep2',
    'scanningStep3',
    'scanningStep4',
  ];

  async function pollJobWithProgress(id) {
    const stepperDots = $$('#scanStepper .step-dot');
    const statusText = $('#statusText');

    // The server scans strictly one job at a time, so a job can spend real time
    // QUEUED behind someone else's slow target. The old loop advanced a fake
    // stepper every tick regardless, capped the text at step 4 forever, and gave
    // up after 90 ticks (~2m42s) — which is what made the UI look frozen while
    // the queue was busy. Poll on a wall clock, and say what is actually true.
    const deadline = Date.now() + 240000;
    let tick = 0;

    while (Date.now() < deadline) {
      const res = await fetch('/api/leaderboard/job/' + encodeURIComponent(id));
      if (!res.ok) throw new Error(t('networkError') || 'Napaka pri poizvedovanju statusa');
      const job = await res.json();
      if (job.status === 'error') throw new Error(job.error || t('scanFailedTarget'));
      if (job.status === 'done' && job.report) {
        const report = job.report;
        report.id = job.reportId;
        return report;
      }

      if (job.status === 'queued') {
        // Waiting for the single scan slot. Do not pretend to be scanning.
        if (statusText) statusText.textContent = t('scanQueued');
        stepperDots.forEach((d, idx) => d.classList.toggle('active', idx === 0));
        tick = 0; // reset tick counter so running starts cleanly from the beginning
      } else {
        let phaseIdx = 0;
        if (job.progress && typeof job.progress.phaseIdx === 'number') {
          phaseIdx = Math.max(0, Math.min(job.progress.phaseIdx, stepperDots.length - 1));
          if (statusText) {
            if (job.progress.msg) {
              const msg = job.progress.msg;
              if (window.i18n.lang() === 'en') {
                if (/DNS zapise/i.test(msg)) statusText.textContent = 'Verifying DNS records and TLS certificate …';
                else if (/varnostne glave/i.test(msg)) statusText.textContent = 'Auditing HTTP security headers and cookies …';
                else if (/hitrost delovanja|Core Web Vitals/i.test(msg)) statusText.textContent = 'Measuring performance and Core Web Vitals …';
                else if (/podstrani/i.test(msg)) statusText.textContent = 'Crawling subpages and policy links …';
                else if (/računanje ocene/i.test(msg)) statusText.textContent = 'Finalizing analysis and computing score …';
                else if (/zaključeno/i.test(msg)) statusText.textContent = 'Completed';
                else statusText.textContent = msg;
              } else {
                statusText.textContent = msg;
              }
            } else if (SCAN_PHASES[phaseIdx]) {
              statusText.textContent = t(SCAN_PHASES[phaseIdx]);
            }
          }
        } else {
          phaseIdx = Math.min(Math.floor(tick / 3), stepperDots.length - 1);
          if (statusText && SCAN_PHASES[phaseIdx]) {
            statusText.textContent = t(SCAN_PHASES[phaseIdx]);
          }
        }
        stepperDots.forEach((d, idx) => d.classList.toggle('active', idx <= phaseIdx));
        tick += 1;
      }
      await new Promise((resolve) => setTimeout(resolve, 1800));
    }

    // Honest timeout: the job is very likely still running server-side, it just
    // did not fit in the browser's patience (usually because it waited in the
    // queue). Say that instead of a bare "timeout".
    throw new Error(t('scanTimeoutSoft'));
  }

  function initSubmitForm() {
    $('#scanForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      let url = $('#urlInput').value.trim();
      if (!url) return;

      // Clean protocol prefix if typed
      url = url.replace(/^https?:\/\//i, '');

      const hideResultsEl = $('#hideResultsCheck');
      const followRedirectsEl = $('#followRedirectsCheck');
      const hideResults = hideResultsEl ? Boolean(hideResultsEl.checked) : false;
      const followRedirects = followRedirectsEl ? Boolean(followRedirectsEl.checked) : true;

      const status = $('#scanStatus');
      const btn = $('#scanBtn');
      status.hidden = false;
      status.classList.remove('is-error', 'is-rate-limited');
      const stepper = $('#scanStepper');
      if (stepper) stepper.style.display = '';
      $$('#scanStepper .step-dot').forEach((d, idx) => d.classList.toggle('active', idx === 0));
      $('#statusText').textContent = t(SCAN_PHASES[0]);
      btn.disabled = true;

      try {
        const res = await fetch('/api/leaderboard/submit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: 'https://' + url,
            hideResults,
            followRedirects,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (res.status === 429 || data.code === 'RATE_LIMITED' || /too many submissions|rate limit/i.test(data.error || '')) {
            const err = new Error(t('rateLimitExceeded'));
            err.isRateLimit = true;
            throw err;
          }
          throw new Error(data.error || t('scanFailed'));
        }

        const report = await pollJobWithProgress(data.job.id);
        report.hideResults = hideResults;
        state.result = report;
        status.hidden = true;
        renderResult(report, { hideResults });
        if (!hideResults) {
          loadBoard();
        }

        // Smooth scroll to result
        document.getElementById('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
      } catch (err) {
        status.hidden = false;
        const stepper = $('#scanStepper');
        if (stepper) stepper.style.display = 'none';

        // A failed scan must not leave the PREVIOUS report on screen. Without
        // this, "DNS resolution failed" was shown above a stale 100/A+ card
        // from an unrelated domain, which reads as if the dead domain scored
        // 100. Clear the card and the cached state together.
        const staleCard = $('#result');
        if (staleCard) staleCard.hidden = true;
        state.result = null;

        if (err.isRateLimit) {
          status.classList.add('is-rate-limited');
          status.classList.remove('is-error');
          $('#statusText').textContent = err.message || t('rateLimitExceeded');
        } else {
          status.classList.add('is-error');
          status.classList.remove('is-rate-limited');
          $('#statusText').textContent = formatScanError(err.message);
        }
      } finally {
        btn.disabled = false;
      }
    });

    const hideCheck = $('#hideResultsCheck');
    if (hideCheck) {
      hideCheck.addEventListener('change', () => {
        const claimFormEl = $('#claimForm');
        if (claimFormEl && !$('#result').hidden) {
          const hide = Boolean(hideCheck.checked);
          claimFormEl.hidden = hide;
          claimFormEl.style.display = hide ? 'none' : '';
        }
      });
    }

    // Sample click handlers
    $$('.chip-sample').forEach((btn) => {
      btn.addEventListener('click', () => {
        const sampleUrl = btn.dataset.url;
        $('#urlInput').value = sampleUrl;
        $('#scanForm').dispatchEvent(new Event('submit', { cancelable: true }));
      });
    });
  }

  const DOMAIN_ORDER = ['security', 'compliance', 'performance', 'accessibility', 'seo', 'quality'];
  const DOMAIN_LABEL_SL = {
    security: 'Varnost',
    compliance: 'GDPR',
    performance: 'CWV',
    accessibility: 'A11y',
    seo: 'SEO',
    quality: 'Koda',
  };
  const DOMAIN_LABEL_EN = {
    security: 'Security',
    compliance: 'GDPR',
    performance: 'CWV',
    accessibility: 'A11y',
    seo: 'SEO',
    quality: 'Code',
  };
  const SEV_LABEL_SL = {
    critical: 'Kritično',
    high: 'Visoko',
    medium: 'Srednje',
    low: 'Nizko',
    info: 'Info',
  };
  const SEV_LABEL_EN = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
  };

  function getDomainLabel(key) {
    const isSl = window.i18n.lang() === 'sl';
    return (isSl ? DOMAIN_LABEL_SL[key] : DOMAIN_LABEL_EN[key]) || key;
  }

  function getSevLabel(sev) {
    const s = String(sev || 'info').toLowerCase();
    const isSl = window.i18n.lang() === 'sl';
    return (isSl ? SEV_LABEL_SL[s] : SEV_LABEL_EN[s]) || s;
  }

  function cleanDisplayHost(rawUrl) {
    if (!rawUrl) return '—';
    try {
      const u = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
      return u.hostname.replace(/^www\./i, '');
    } catch (e) {
      return String(rawUrl).replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    }
  }

  function renderLowLevelTelemetry(report) {
    const grid = $('#lowLevelTelemetry');
    if (!grid) return;
    grid.textContent = '';
    const tele = report.telemetry || report.meta || {};
    const wire = tele.wire || (report.meta && report.meta.wire) || {};
    const tls = tele.tls || (report.meta && report.meta.tls) || {};
    const dns = tele.dns || (report.meta && report.meta.dns) || {};
    const cwv = tele.cwv || (report.meta && report.meta.cwv) || {};
    const isSl = window.i18n.lang() === 'sl';

    const ledger = el('div', 'll-clean-ledger');

    const addSpecRow = (term, valNodeOrText) => {
      const row = el('div', 'll-clean-row ll-spec-row');
      row.appendChild(el('span', 'll-clean-term', term));
      if (typeof valNodeOrText === 'string') {
        const valSpan = el('span', 'll-clean-val');
        valSpan.appendChild(el('span', 'll-clean-text', valNodeOrText));
        row.appendChild(valSpan);
      } else {
        row.appendChild(valNodeOrText);
      }
      ledger.appendChild(row);
    };

    // 1. Server & HTTP
    const status = wire.status || report.status || 200;
    const ttfb = wire.ttfbMs ? `${wire.ttfbMs} ms TTFB` : null;
    const ipPart = report.resolvedIp || '—';
    addSpecRow(
      isSl ? 'Strežnik & odziv' : 'Server & Response',
      [ipPart, `HTTP ${status}`, ttfb].filter(Boolean).join(' · ')
    );

    // 2. TLS & Certificate
    const tlsWrap = el('span', 'll-clean-val');
    const isTls13 = tls.protocol && /TLSv1\.3/.test(tls.protocol);
    const dot = el('span', 'll-status-dot ' + (isTls13 ? 'good' : tls.protocol ? 'warn' : 'bad'));
    tlsWrap.appendChild(dot);
    const protoText = tls.protocol ? `${tls.protocol} (${tls.alpn || 'h2'})` : (isSl ? 'Brez TLS (HTTP)' : 'Plain HTTP');
    const certText = tls.issuer
      ? ` · ${tls.issuer}${tls.daysToExpiry != null ? ` (${tls.daysToExpiry}d)` : ''}`
      : '';
    const tlsTextSpan = el('span', 'll-clean-text');
    tlsTextSpan.appendChild(el('span', 'll-val-part nowrap', protoText));
    if (certText) {
      tlsTextSpan.appendChild(el('span', 'll-val-part', certText));
    }
    tlsWrap.appendChild(tlsTextSpan);
    addSpecRow(isSl ? 'TLS & certifikat' : 'TLS & Certificate', tlsWrap);

    // 3. Speed & Compression (CWV + Wire)
    const speedParts = [];
    const lcpVal = cwv.lcp != null ? cwv.lcp : cwv.lcpMs;
    const tbtVal = cwv.tbt != null ? cwv.tbt : cwv.tbtMs;
    const fcpVal = cwv.fcp != null ? cwv.fcp : cwv.fcpMs;
    if (lcpVal != null && lcpVal > 0) speedParts.push(`LCP ${Math.round(lcpVal)} ms`);
    else if (fcpVal != null && fcpVal > 0) speedParts.push(`FCP ${Math.round(fcpVal)} ms`);
    if (tbtVal != null) speedParts.push(`TBT ${Math.round(tbtVal)} ms`);
    if (cwv.cls != null) speedParts.push(`CLS ${Number(cwv.cls).toFixed(2)}`);
    if (wire.encoding && wire.encoding !== 'none') speedParts.push(wire.encoding);
    if (wire.rawBytes) speedParts.push(`${(wire.rawBytes / 1024).toFixed(1)} KB`);
    addSpecRow(
      isSl ? 'Hitrost & prenos' : 'Vitals & Payload',
      speedParts.length ? speedParts.join(' · ') : '—'
    );

    // 4. DNS Security Indicators (Clean subtle pills with status dots)
    const dnsWrap = el('div', 'll-dns-clean-row');
    const dnsItems = [
      ['SPF', dns.spf],
      ['DMARC', dns.dmarc],
      ['DNSSEC', dns.dnssec],
      ['CAA', dns.caa],
    ];
    if (dns.hasMx !== false) {
      dnsItems.push(['MTA-STS', dns.mtaSts]);
    }
    dnsItems.forEach(([label, ok]) => {
      const chip = el('span', 'll-dns-chip ' + (ok ? 'is-ok' : 'is-miss'));
      chip.appendChild(el('span', 'll-chip-dot'));
      chip.appendChild(document.createTextNode(label));
      dnsWrap.appendChild(chip);
    });
    addSpecRow(isSl ? 'DNS zaščita' : 'DNS Security', dnsWrap);

    // 5. Detected Stack & Scope
    const stackArr = (tele.tech && tele.tech.length ? tele.tech : []).slice(0, 4);
    const stackStr = stackArr.length ? stackArr.join(', ') : (isSl ? 'Lastna izvedba' : 'Custom');
    const scopeStr = `${tele.crawledPages || 1} ${isSl ? 'str.' : 'pg'}, ${tele.scriptCount || 0} JS`;
    addSpecRow(isSl ? 'Tehnološki sklad' : 'Tech Stack', `${stackStr} · ${scopeStr}`);

    // 6. Infrastructure (Shodan InternetDB)
    const shodan = tele.shodan || (report.meta && report.meta.shodan);
    const shodanWrap = el('span', 'll-clean-val');
    if (shodan && !shodan.error && (shodan.isCdn || (shodan.ports && shodan.ports.length) || (shodan.vulns && shodan.vulns.length))) {
      if (shodan.isCdn) {
        shodanWrap.appendChild(el('span', 'll-status-dot good'));
        const pList = shodan.ports && shodan.ports.length ? shodan.ports.slice(0, 5).join(', ') : '80, 443';
        const textSpan = el('span', 'll-clean-text');
        textSpan.appendChild(el('span', 'll-val-part nowrap', 'Cloudflare Edge CDN'));
        textSpan.appendChild(el('span', 'll-val-sep', '·'));
        textSpan.appendChild(el('span', 'll-val-part nowrap', pList));
        textSpan.appendChild(el('span', 'll-val-sep', '·'));
        textSpan.appendChild(el('span', 'll-val-part nowrap', isSl ? '0 ranljivosti (CVE)' : '0 CVE vulnerabilities'));
        shodanWrap.appendChild(textSpan);
      } else if (shodan.vulns && shodan.vulns.length > 0) {
        shodanWrap.appendChild(el('span', 'll-status-dot bad'));
        const pList = shodan.ports && shodan.ports.length ? shodan.ports.join(', ') : '—';
        const textSpan = el('span', 'll-clean-text');
        textSpan.appendChild(el('span', 'll-val-part', pList));
        textSpan.appendChild(el('span', 'll-val-sep', '·'));
        textSpan.appendChild(el('span', 'll-val-part nowrap', isSl ? `${shodan.vulns.length} znanih CVE ranljivosti` : `${shodan.vulns.length} known CVE vulnerabilities`));
        shodanWrap.appendChild(textSpan);
      } else {
        shodanWrap.appendChild(el('span', 'll-status-dot good'));
        const pList = shodan.ports && shodan.ports.length ? (isSl ? 'Porti: ' + shodan.ports.join(', ') : 'Ports: ' + shodan.ports.join(', ')) : (isSl ? 'Zaprto' : 'Closed');
        const textSpan = el('span', 'll-clean-text');
        textSpan.appendChild(el('span', 'll-val-part', pList));
        textSpan.appendChild(el('span', 'll-val-sep', '·'));
        textSpan.appendChild(el('span', 'll-val-part nowrap', isSl ? '0 znanih CVE ranljivosti' : '0 known CVE vulnerabilities'));
        shodanWrap.appendChild(textSpan);
      }
    } else {
      shodanWrap.appendChild(el('span', 'll-status-dot good'));
      const textSpan = el('span', 'll-clean-text', isSl ? 'Brez odprtih ranljivih portov (čista cona)' : 'No exposed vulnerability ports');
      shodanWrap.appendChild(textSpan);
    }
    addSpecRow(isSl ? 'Infrastruktura (Shodan)' : 'Infrastructure (Shodan)', shodanWrap);

    // 7. Field Experience (CrUX)
    const crux = tele.crux || (report.meta && report.meta.crux);
    const cruxWrap = el('span', 'll-clean-val');
    if (crux && crux.category && crux.category !== 'INSUFFICIENT_DATA' && crux.category !== 'UNAVAILABLE') {
      const cruxCat = String(crux.category).toUpperCase();
      const dotCls = cruxCat === 'FAST' ? 'good' : cruxCat === 'AVERAGE' ? 'warn' : 'bad';
      cruxWrap.appendChild(el('span', 'll-status-dot ' + dotCls));
      const lcpStr = crux.metrics && crux.metrics.lcp ? ' · LCP ' + Math.round(crux.metrics.lcp) + 'ms' : '';
      const clsStr = crux.metrics && crux.metrics.cls != null ? ' · CLS ' + Number(crux.metrics.cls).toFixed(2) : '';
      const textSpan = el('span', 'll-clean-text', `Google CrUX: ${cruxCat}${lcpStr}${clsStr}`);
      cruxWrap.appendChild(textSpan);
    } else if (crux && crux.category === 'INSUFFICIENT_DATA') {
      cruxWrap.appendChild(el('span', 'll-status-dot neutral'));
      const textSpan = el('span', 'll-clean-text', isSl ? 'Ni zadostnega 28d obiska za Googlov terenski certifikat' : 'Insufficient 28-day real-user field volume');
      cruxWrap.appendChild(textSpan);
    } else {
      cruxWrap.appendChild(el('span', 'll-status-dot neutral'));
      const textSpan = el('span', 'll-clean-text', isSl ? 'Ni terenskih podatkov za to domeno' : 'No real-user field data available');
      cruxWrap.appendChild(textSpan);
    }
    addSpecRow(isSl ? 'Uporabniške meritve (CrUX)' : 'Field Experience (CrUX)', cruxWrap);

    // 8. Certificate Transparency Reconnaissance (CT Subdomains)
    const ct = tele.ct || (report.meta && report.meta.ct);
    const ctWrap = el('span', 'll-clean-val');
    if (ct && ct.count > 0) {
      const stagingLive = Array.isArray(ct.stagingLive) ? ct.stagingLive : [];
      const stagingHist = Array.isArray(ct.stagingHistorical)
        ? ct.stagingHistorical
        : (Array.isArray(ct.staging) && !ct.stagingLive ? ct.staging : []);
      const hasLiveStaging = stagingLive.length > 0;
      const hasHistStaging = stagingHist.length > 0;
      const dotCls = hasLiveStaging ? 'bad' : hasHistStaging ? 'warn' : 'good';
      ctWrap.appendChild(el('span', 'll-status-dot ' + dotCls));

      const repTarget = cleanDisplayHost(report.target || report.finalUrl || '');
      const cleanSubName = (sub) => {
        let name = String(sub || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
        if (repTarget && name.endsWith('.' + repTarget)) {
          name = name.slice(0, -(repTarget.length + 1));
        }
        return name || sub;
      };

      let stagingNote = '';
      if (hasLiveStaging) {
        const subNames = stagingLive.slice(0, 2).map(cleanSubName).join(', ');
        const count = stagingLive.length;
        if (isSl) {
          const word = count === 1 ? 'testna' : count === 2 ? 'testni' : count < 5 ? 'testne' : 'testnih';
          stagingNote = `${count} ${word}: ${subNames} [LIVE]`;
        } else {
          stagingNote = `${count} live: ${subNames} [LIVE]`;
        }
      } else if (hasHistStaging) {
        const subNames = stagingHist.slice(0, 2).map(cleanSubName).join(', ');
        const count = stagingHist.length;
        if (isSl) {
          const word = count === 1 ? 'zgodovinska' : count === 2 ? 'zgodovinski' : count < 5 ? 'zgodovinske' : 'zgodovinskih';
          stagingNote = `${count} ${word}: ${subNames} [NXDOMAIN]`;
        } else {
          stagingNote = `${count} historical: ${subNames} [NXDOMAIN]`;
        }
      } else if (ct.sample && ct.sample.length > 1) {
        const otherSubs = ct.sample
          .filter((s) => !s.startsWith('www.') && cleanDisplayHost(s) !== repTarget)
          .slice(0, 2)
          .map(cleanSubName);
        if (otherSubs.length) {
          stagingNote = otherSubs.join(', ');
        }
      }

      const textSpan = el('span', 'll-clean-text');
      const countPart = el('span', 'll-val-part nowrap', `${ct.count} ${isSl ? 'zaznanih poddomen' : 'discovered subdomains'}`);
      textSpan.appendChild(countPart);
      if (stagingNote) {
        const notePart = el('span', 'll-val-part nowrap', ` (${stagingNote})`);
        textSpan.appendChild(notePart);
      }
      ctWrap.appendChild(textSpan);
    } else {
      ctWrap.appendChild(el('span', 'll-status-dot neutral'));
      const textSpan = el('span', 'll-clean-text', isSl ? 'Samo krovna domena (brez poddomen v CT logih)' : 'Apex only (no subdomains indexed)');
      ctWrap.appendChild(textSpan);
    }
    addSpecRow(isSl ? 'Poddomene (CT Recon)' : 'Subdomains (CT Recon)', ctWrap);

    grid.appendChild(ledger);
  }

  function renderResult(report, opts = {}) {
    const card = $('#result');
    card.hidden = false;
    const isSl = window.i18n.lang() === 'sl';
    const degInfo = normalizeDegradedInfo(report);
    const isDegraded = Boolean(degInfo);

    // Prominent Warning Banner if scan was blocked/degraded
    const degradedBanner = $('#degradedBanner');
    if (degradedBanner) {
      if (isDegraded) {
        degradedBanner.hidden = false;
        degradedBanner.textContent = '';

        const headKey = degInfo.kind === 'waf'
          ? 'degradedWafTitle'
          : degInfo.kind === 'render'
            ? 'degradedRenderTitle'
            : 'degradedPartialTitle';
        const headTitle = degInfo.headersOnly
          ? (isSl ? 'Nepopolna analiza — WAF je blokiral izvorne HTTP glave' : 'Partial scan — WAF blocked origin HTTP headers')
          : t(headKey);
        const head = el('div', 'degraded-alert-head');
        const headIcon = document.createElement('span');
        headIcon.setAttribute('aria-hidden', 'true');
        headIcon.innerHTML = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2.2L14.2 13H1.8L8 2.2z"/><line x1="8" y1="6.4" x2="8" y2="9.6"/><circle cx="8" cy="11.4" r="0.6" fill="currentColor" stroke="none"/></svg>';
        head.appendChild(headIcon);
        head.appendChild(el('span', '', headTitle));
        degradedBanner.appendChild(head);

        const capVal = degInfo.scoreCap || (degInfo.kind === 'waf' ? 70 : 79);
        const uncappedNote = typeof degInfo.scoreUncapped === 'number'
          ? (isSl ? ` (neomejena ocena pred omejitvijo: ${degInfo.scoreUncapped})` : ` (uncapped pre-cap score: ${degInfo.scoreUncapped})`)
          : '';
        const unrunNote = degInfo.unrunChecks && degInfo.unrunChecks.length
          ? ` ${t('degradedUnrunLabel')} ${degInfo.unrunChecks.join(', ')}.`
          : '';
        const bodyText = degInfo.headersOnly
          ? (isSl
              ? `Ciljni WAF (${degInfo.wafProvider || 'bot zaščita'}) je blokiral neposredni zajem HTTP glav; vsebina strani je bila pregledana prek nadomestnega zajema, zato varnostne glave niso preverjene in je končna ocena omejena na ${capVal}${uncappedNote}.${unrunNote}`
              : `Target WAF (${degInfo.wafProvider || 'bot protection'}) blocked direct HTTP header capture; page content was analyzed via fallback rendering, so origin security headers remain unverified and the score is capped at ${capVal}${uncappedNote}.${unrunNote}`)
          : degInfo.kind === 'waf'
            ? (isSl
                ? `Ciljni strežnik ali WAF (${degInfo.wafProvider || 'bot zaščita'}) je prestregel samodejni pregled. Pregledi vsebine niso mogli teči, zato je končna ocena omejena na ${capVal}${uncappedNote}.${unrunNote}`
                : `Target firewall or bot protection (${degInfo.wafProvider || 'WAF'}) intercepted the automated scan. Content checks could not run, so the final score is capped at ${capVal}${uncappedNote}.${unrunNote}`)
            : degInfo.kind === 'render'
              ? (isSl
                  ? `Headless Chromium izris ni bil na voljo, zato meritve hitrosti (CWV) in izrisane dostopnosti niso tekle. Ocena je omejena na ${capVal}${uncappedNote}.${unrunNote}`
                  : `Headless Chromium rendering was unavailable, so lab CWV and rendered accessibility passes did not run. The score is capped at ${capVal}${uncappedNote}.${unrunNote}`)
              : (isSl
                  ? `Nekateri moduli za preverjanje niso mogli teči. Končna ocena je omejena na ${capVal}${uncappedNote}.${unrunNote}`
                  : `Some verification passes did not complete. The final score is capped at ${capVal}${uncappedNote}.${unrunNote}`);

        const body = el('div', 'degraded-alert-body', bodyText);
        degradedBanner.appendChild(body);

        const actions = el('div', 'degraded-alert-actions');
        const retryBtn = el('button', 'degraded-retry-btn', t('degradedRetryBtn'));
        retryBtn.type = 'button';
        retryBtn.onclick = () => {
          $('#urlInput').value = report.finalUrl || report.target;
          $('#scanForm').dispatchEvent(new Event('submit', { cancelable: true }));
        };
        actions.appendChild(retryBtn);
        degradedBanner.appendChild(actions);
      } else {
        degradedBanner.hidden = true;
      }
    }

    const isHiddenResults = Boolean(
      (opts && opts.hideResults) ||
      report.hideResults ||
      ($('#hideResultsCheck') && $('#hideResultsCheck').checked)
    );
    const claimFormEl = $('#claimForm');
    if (claimFormEl) {
      claimFormEl.hidden = isHiddenResults;
      claimFormEl.style.display = isHiddenResults ? 'none' : '';
    }

    const hostClean = cleanDisplayHost(report.finalUrl || report.target);
    $('#resultHost').textContent = hostClean;
    $('#resultScore').textContent = String(report.score);

    const relSlot = $('#resultReliability');
    if (relSlot) {
      relSlot.textContent = '';
      if (degInfo) {
        const badgeNode = buildReliabilityBadge(degInfo, 'tip-result-hero', { showUncapped: true });
        if (badgeNode) relSlot.appendChild(badgeNode);
        relSlot.hidden = false;
      } else {
        relSlot.hidden = true;
      }
    }

    let rawGrade = (report.grade || 'C').toUpperCase();
    if (rawGrade === 'A' && report.score >= 97) rawGrade = 'A+';
    const gradeLetter = rawGrade.charAt(0).toLowerCase();
    const gradeEl = $('#resultGrade');
    gradeEl.textContent = rawGrade;
    gradeEl.className = 'card-grade-badge result-grade-badge grade-' + gradeLetter;
    gradeEl.removeAttribute('title');

    const dateStr = new Date(report.startedAt || Date.now()).toLocaleString(isSl ? 'sl-SI' : 'en-GB', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
    const durStr = report.durationMs ? `${(report.durationMs / 1000).toFixed(1)} s` : null;
    const privacyStr = isHiddenResults
      ? (isSl ? 'Skrito z lestvice' : 'Hidden from index')
      : (isSl ? 'Shranjene le ocene 1–100' : 'Only 1–100 scores stored');
    $('#resultMeta').textContent = [dateStr, durStr, privacyStr].filter(Boolean).join(' · ');

    const allFindings = (report.findings || [])
      .slice()
      .sort((a, b) => sevRank(b.severity) - sevRank(a.severity));

    let activeDomainFilter = 'all';
    let expandedFindingIndex = 0;

    // Populate summary badges in the findings header
    const summaryBadges = $('#findingsSummaryBadges');
    if (summaryBadges) {
      summaryBadges.textContent = '';
      const highCount = allFindings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
      const medCount = allFindings.filter((f) => f.severity === 'medium').length;
      const lowCount = allFindings.filter((f) => f.severity === 'low' || f.severity === 'info').length;
      if (highCount > 0) {
        summaryBadges.appendChild(
          el('span', 'finding-sev-pill sev-high', `${highCount} ${isSl ? 'visoko' : 'high'}`)
        );
      }
      if (medCount > 0) {
        summaryBadges.appendChild(
          el('span', 'finding-sev-pill sev-medium', `${medCount} ${isSl ? 'srednje' : 'medium'}`)
        );
      }
      if (lowCount > 0) {
        summaryBadges.appendChild(
          el('span', 'finding-sev-pill sev-low', `${lowCount} ${isSl ? 'nizko' : 'low'}`)
        );
      }
    }

    const list = $('#resultFindings');
    const filterTabs = $('#findingsFilterTabs');
    const bars = $('#domainBars');

    function setDomainFilter(key) {
      activeDomainFilter = key;
      expandedFindingIndex = 0;
      $$('#findingsFilterTabs .tab-btn').forEach((b) => {
        b.classList.toggle('active', b.dataset.domainKey === key);
      });
      $$('#domainBars .card-domain-item').forEach((item) => {
        item.classList.toggle('active-filter', item.dataset.domainKey === key);
      });
      drawFindingsList();
    }

    // 6 Category Score Cards (Identical to Leaderboard Card Expansion + Clickable Filter)
    bars.textContent = '';
    for (const key of DOMAIN_ORDER) {
      const d = (report.domains || {})[key];
      if (!d) continue;
      const item = el('div', 'card-domain-item result-domain-card' + (d.unverified ? ' is-unverified' : ''));
      item.dataset.domainKey = key;
      const dMeta = el('div', 'card-domain-meta');
      dMeta.appendChild(el('span', 'card-domain-name', getDomainLabel(key)));
      const dScoreGroup = el('span', 'card-domain-score-group');
      if (d.unverified) {
        dScoreGroup.appendChild(el('span', 'domain-unverified-tag', t('degradedUnverifiedChip')));
      }
      dScoreGroup.appendChild(el('span', 'card-domain-score', String(d.score)));
      dMeta.appendChild(dScoreGroup);
      item.appendChild(dMeta);

      const track = el('div', 'card-domain-track');
      const fill = el('div', 'card-domain-fill' + (d.unverified ? ' unverified' : d.score < 55 ? ' low' : d.score < 75 ? ' medium' : ''));
      fill.style.width = Math.max(0, Math.min(100, d.score)) + '%';
      track.appendChild(fill);
      item.appendChild(track);

      item.addEventListener('click', () => {
        const nextKey = activeDomainFilter === key ? 'all' : key;
        setDomainFilter(nextKey);
      });
      bars.appendChild(item);
    }

    wireHintTooltips(card);

    renderLowLevelTelemetry(report);

    function drawFindingsList() {
      list.textContent = '';
      const filtered =
        activeDomainFilter === 'all'
          ? allFindings
          : allFindings.filter((f) => f.domain === activeDomainFilter);

      if (filtered.length === 0) {
        const emptyLi = el('li', 'finding-row-card empty');
        emptyLi.textContent = isSl
          ? 'V tem področju ni zaznanih pomanjkljivosti (100/100).'
          : 'No issues detected in this category (100/100).';
        list.appendChild(emptyLi);
        return;
      }

      filtered.forEach((f, idx) => {
        const isExpanded = idx === expandedFindingIndex;
        const sev = String(f.severity || 'info').toLowerCase();
        const li = el('li', 'finding-row-card' + (isExpanded ? ' expanded' : ''));

        // Compact single-line header row (matches .floating-site-card)
        const mainRow = el('div', 'finding-row-main');
        const leftGroup = el('div', 'finding-row-lead');
        leftGroup.appendChild(el('span', 'finding-sev-pill sev-' + sev, getSevLabel(sev)));
        leftGroup.appendChild(el('span', 'finding-row-title', f.title || ''));
        mainRow.appendChild(leftGroup);

        const rightGroup = el('div', 'finding-row-tail');
        if (f.domain) {
          rightGroup.appendChild(el('span', 'finding-cat-pill', getDomainLabel(f.domain)));
        }
        const chev = el('span', 'finding-chevron');
        chev.innerHTML =
          '<svg viewBox="0 0 20 20" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="5 8 10 13 15 8"></polyline></svg>';
        rightGroup.appendChild(chev);
        mainRow.appendChild(rightGroup);
        li.appendChild(mainRow);

        // Expandable detail drawer (only 1 open at a time -> zero doom scrolling)
        const expandPanel = el('div', 'finding-expand-panel');
        const expandInner = el('div', 'finding-expand-inner');

        if (f.detail) {
          expandInner.appendChild(el('p', 'finding-detail-text', f.detail));
        }

        if (f.evidence || f.fix) {
          const boxesGrid = el('div', 'finding-detail-boxes');
          if (f.evidence) {
            const evBox = el('div', 'finding-info-box evidence-box');
            const evHead = el('div', 'finding-box-label', isSl ? 'Opaženo v odzivu' : 'Observed Evidence');
            if (f.id) {
              evHead.appendChild(el('span', 'finding-rule-code', f.id));
            }
            evBox.appendChild(evHead);
            evBox.appendChild(el('pre', 'finding-evidence-pre', String(f.evidence)));
            boxesGrid.appendChild(evBox);
          }
          if (f.fix) {
            const fixBox = el('div', 'finding-info-box fix-box');
            fixBox.appendChild(el('div', 'finding-box-label', isSl ? 'Priporočena odprava' : 'Recommended Fix'));
            fixBox.appendChild(el('div', 'finding-fix-text', f.fix));
            boxesGrid.appendChild(fixBox);
          }
          expandInner.appendChild(boxesGrid);
        }

        const actionsRow = el('div', 'finding-actions-row');
        const copyFixBtn = el('button', 'btn-copy-ai-fix');
        copyFixBtn.type = 'button';
        copyFixBtn.innerHTML =
          '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> <span>' +
          t('copyFixBtn') +
          '</span>';
        copyFixBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          const prompt = buildSingleAiPrompt(report, f);
          copyToClipboard(prompt, copyFixBtn, t('copiedDone'));
        });
        actionsRow.appendChild(copyFixBtn);
        expandInner.appendChild(actionsRow);

        expandPanel.appendChild(expandInner);
        li.appendChild(expandPanel);

        mainRow.addEventListener('click', () => {
          const alreadyOpen = li.classList.contains('expanded');
          $$('#resultFindings .finding-row-card.expanded').forEach((c) => c.classList.remove('expanded'));
          if (!alreadyOpen) {
            li.classList.add('expanded');
            expandedFindingIndex = idx;
          } else {
            expandedFindingIndex = -1;
          }
        });

        list.appendChild(li);
      });
    }

    if (filterTabs) {
      filterTabs.textContent = '';
      const tabDefs = [
        ['all', (isSl ? 'Vse' : 'All') + ` (${allFindings.length})`],
        ...DOMAIN_ORDER.map((k) => {
          const count = allFindings.filter((f) => f.domain === k).length;
          return [k, `${getDomainLabel(k)} (${count})`];
        }),
      ];
      tabDefs.forEach(([key, label]) => {
        const btn = el('button', 'tab-btn' + (key === activeDomainFilter ? ' active' : ''), label);
        btn.type = 'button';
        btn.dataset.domainKey = key;
        btn.addEventListener('click', () => setDomainFilter(key));
        filterTabs.appendChild(btn);
      });
    }

    drawFindingsList();

    const copyAllBtn = $('#btnCopyAllPlan');
    if (copyAllBtn) {
      if (allFindings.length > 0) {
        copyAllBtn.hidden = false;
        const copySpan = copyAllBtn.querySelector('span');
        if (copySpan) copySpan.textContent = t('copyPlanBtn');
        copyAllBtn.onclick = () => {
          const prompt = buildFullAiPrompt(report, allFindings);
          copyToClipboard(prompt, copyAllBtn, t('copiedDone'));
        };
      } else {
        copyAllBtn.hidden = true;
      }
    }

    const privacyCallout = $('#findingsPrivacyCallout');
    if (privacyCallout) privacyCallout.hidden = true;
    list.hidden = false;

    $('#verdict').hidden = true;
    $('#claimBtn').disabled = false;
    $('#claimForm').dataset.reportId = report.id || '';

    // Auto-detect & pre-populate claim form from scan fingerprint and existing claim
    autoPopulateClaimForm(report);
  }
  window.__renderDeepResult = renderResult;

  function autoPopulateClaimForm(report) {
    if (!report) return;

    // Helper to select an option in a <select> or fall back to custom input
    function setSelectOrCustom(selectId, val) {
      const sel = $('#' + selectId);
      if (!sel || !val) return;
      const valLower = String(val).toLowerCase();
      const match = Array.from(sel.options).find(
        (o) => o.value.toLowerCase() === valLower || o.text.toLowerCase().includes(valLower)
      );
      if (match) {
        sel.value = match.value;
        sel.dispatchEvent(new Event('change'));
      } else {
        sel.value = 'custom';
        sel.dispatchEvent(new Event('change'));
        const customEl = $('#' + selectId + 'Custom');
        if (customEl) customEl.value = val;
      }
    }

    function setKind(val) {
      const kindInput = $('#kind');
      if (kindInput) kindInput.value = val;
      $$('#kindSelector .kind-pill-btn').forEach((b) => {
        b.classList.toggle('active', b.dataset.value === val);
      });
      const agencyChips = $('#agencyChips');
      if (agencyChips) agencyChips.hidden = val !== 'agency';
    }

    // 1. First check if domain has an existing claim in report or loaded leaderboard
    const cleanHost = cleanDisplayHost(report.finalUrl || report.target || '');
    const existingSite = (state.rows || []).find((s) => cleanDisplayHost(s.host || s.target || '') === cleanHost);
    const existingClaim = report.claim || (existingSite && existingSite.claim);

    if (existingClaim && (existingClaim.builderName || existingClaim.builderKind || existingClaim.platform || existingClaim.harness || existingClaim.model)) {
      if (existingClaim.builderKind && existingClaim.builderKind !== 'unknown') {
        setKind(existingClaim.builderKind);
      }
      if (existingClaim.builderName) {
        const bNameEl = $('#builderName');
        if (bNameEl) bNameEl.value = existingClaim.builderName;
      }
      if (existingClaim.platform) {
        setSelectOrCustom('platform', existingClaim.platform);
      }
      if (existingClaim.harness) {
        setSelectOrCustom('harness', existingClaim.harness);
      }
      if (existingClaim.model) {
        setSelectOrCustom('model', existingClaim.model);
      }
      return;
    }

    // Try fetching from server in case not in current rows view
    if (cleanHost && cleanHost !== '—') {
      fetch('/api/leaderboard/site/' + encodeURIComponent(cleanHost))
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          const sub = data && data.submissions && data.submissions[0];
          if (sub) {
            if (sub.builderKind && sub.builderKind !== 'unknown') setKind(sub.builderKind);
            if (sub.builderName) {
              const bNameEl = $('#builderName');
              if (bNameEl && !bNameEl.value) bNameEl.value = sub.builderName;
            }
            if (sub.platform) setSelectOrCustom('platform', sub.platform);
            if (sub.harness) setSelectOrCustom('harness', sub.harness);
            if (sub.model) setSelectOrCustom('model', sub.model);
          }
        })
        .catch(() => {});
    }

    // 2. Otherwise auto-detect from the scan telemetry
    const build = (report.telemetry && report.telemetry.build) || (report.meta && report.meta.build) || {};
    const flags = build.flags || {};
    const agentFiles = Array.isArray(build.agentFiles) ? build.agentFiles : [];

    // Platform
    const detectedPlat = build.platform;
    if (detectedPlat) {
      setSelectOrCustom('platform', detectedPlat);
    }

    // Harness / Tool
    let detectedHarness = null;
    if (flags.v0Badge) detectedHarness = 'v0';
    else if (flags.lovableBadge) detectedHarness = 'Lovable';
    else if (flags.boltBadge) detectedHarness = 'Bolt.new';
    else if (flags.replitBadge) detectedHarness = 'Replit Agent';
    else if (flags.marblismBadge) detectedHarness = 'Marblism';
    else if (flags.createXyzBadge) detectedHarness = 'Create.xyz';
    else if (agentFiles.some((f) => f.toLowerCase().includes('claude'))) detectedHarness = 'Claude Code';
    else if (agentFiles.some((f) => f.toLowerCase().includes('cursor'))) detectedHarness = 'Cursor';
    else if (agentFiles.some((f) => f.toLowerCase().includes('gemini') || f.toLowerCase().includes('agents.md'))) detectedHarness = 'Antigravity';
    else if (agentFiles.some((f) => f.toLowerCase().includes('windsurf'))) detectedHarness = 'Windsurf';
    else if (agentFiles.some((f) => f.toLowerCase().includes('cline'))) detectedHarness = 'Cline';
    else if (agentFiles.some((f) => f.toLowerCase().includes('copilot'))) detectedHarness = 'GitHub Copilot';

    if (detectedHarness) {
      setSelectOrCustom('harness', detectedHarness);
    }

    // Builder Name
    let detectedName = null;
    if (build.footerText) {
      const m =
        build.footerText.match(/(?:razvil(?:i)?|razvito v|oblikovanje|izdelava spletne strani|izdelava|made by|crafted by|developed by|designed by|built by)\s*:?\s*([A-ZŠĐČĆŽ0-9][A-Za-z0-9\sŠĐČĆŽšđčćž.-]{2,35})/i) ||
        build.footerText.match(/(?:©|\(c\)|copyright)\s*(?:\d{4}\s*)?([A-ZŠĐČĆŽ][A-Za-z0-9\sŠĐČĆŽšđčćž.-]{2,40}?\s*(?:d\.o\.o\.|s\.p\.|d\.d\.|ltd|llc|gmbh))/i);
      if (m && m[1]) {
        detectedName = m[1].replace(/[,.|-]+$/, '').trim();
      }
    }
    if (!detectedName && Array.isArray(build.jsonLdNames)) {
      const org = build.jsonLdNames.find((n) => /\b(?:d\.o\.o|s\.p|studio|agency|agencija)\b/i.test(n));
      if (org) detectedName = org.trim();
    }
    if (!detectedName && build.humansTxt) {
      const hm = build.humansTxt.match(/(?:developer|author|site|agency|studio|maker|team)\s*:?\s*([A-Za-z0-9\sŠĐČĆŽšđčćž.-]{2,35})/i);
      if (hm && hm[1]) detectedName = hm[1].trim();
    }

    if (detectedName) {
      const bNameEl = $('#builderName');
      if (bNameEl) bNameEl.value = detectedName;
    }

    // Builder Kind
    if (detectedHarness || flags.selfDeclaredAI || agentFiles.length > 0) {
      setKind('ai');
    } else if (detectedName && /\b(?:d\.o\.o|s\.p|studio|agency|agencija|digital|group|d\.d\.)\b/i.test(detectedName)) {
      setKind('agency');
    } else if (detectedName) {
      setKind('solo');
    } else {
      setKind('unknown');
    }
  }

  function sevRank(s) {
    return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] || 0;
  }

  function populateChipIcons() {
    if (!window.BRAND_ICONS) return;
    $$('#harnessChips .chip-hint').forEach((btn) => {
      const val = btn.dataset.val;
      const svg = window.BRAND_ICONS.getIconForName(val);
      if (svg && !btn.querySelector('.chip-icon-wrap')) {
        const wrap = document.createElement('span');
        wrap.className = 'chip-icon-wrap';
        wrap.innerHTML = svg;
        btn.prepend(wrap);
      }
    });

    $$('#modelChips .chip-hint').forEach((btn) => {
      const val = btn.dataset.val;
      const svg = window.BRAND_ICONS.getIconForName(val);
      if (svg && !btn.querySelector('.chip-icon-wrap')) {
        const wrap = document.createElement('span');
        wrap.className = 'chip-icon-wrap';
        wrap.innerHTML = svg;
        btn.prepend(wrap);
      }
    });
  }

  /* ---------------- Claim Form Interactions ---------------- */

  function initClaimForm() {
    populateChipIcons();

    // Kind segmented selector
    const kindBtns = $$('#kindSelector button, #kindSelector .kind-pill-btn');
    const kindInput = $('#kind');
    const agencyChips = $('#agencyChips');

    kindBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        kindBtns.forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        const val = btn.dataset.value;
        kindInput.value = val;

        // Dynamic visibility helpers
        if (agencyChips) agencyChips.hidden = val !== 'agency';
      });
    });

    // Toggle custom text input for harness
    const harnessSelect = $('#harness');
    const harnessCustom = $('#harnessCustom');
    if (harnessSelect && harnessCustom) {
      harnessSelect.addEventListener('change', () => {
        const isCustom = harnessSelect.value === 'custom';
        harnessCustom.hidden = !isCustom;
        if (isCustom) harnessCustom.focus();
      });
    }

    // Toggle custom text input for model
    const modelSelect = $('#model');
    const modelCustom = $('#modelCustom');
    if (modelSelect && modelCustom) {
      modelSelect.addEventListener('change', () => {
        const isCustom = modelSelect.value === 'custom';
        modelCustom.hidden = !isCustom;
        if (isCustom) modelCustom.focus();
      });
    }

    // Chip hints click to fill inputs or selects
    $$('.chip-hint').forEach((chip) => {
      chip.addEventListener('click', () => {
        const targetId = chip.dataset.for;
        const targetVal = chip.dataset.val || chip.textContent.trim();
        const targetEl = $('#' + targetId);
        if (!targetEl) return;

        // Mark active chip in its cluster
        if (chip.parentElement) {
          chip.parentElement.querySelectorAll('.chip-hint').forEach((c) => c.classList.remove('active'));
          chip.classList.add('active');
        }

        if (targetEl.tagName === 'SELECT') {
          const opt = Array.from(targetEl.options).find(
            (o) => o.value.toLowerCase() === targetVal.toLowerCase() || o.text.toLowerCase().includes(targetVal.toLowerCase())
          );
          if (opt) {
            targetEl.value = opt.value;
            targetEl.dispatchEvent(new Event('change'));
          } else {
            targetEl.value = 'custom';
            targetEl.dispatchEvent(new Event('change'));
            const customInput = $('#' + targetId + 'Custom');
            if (customInput) {
              customInput.value = targetVal;
              customInput.focus();
            }
          }
        } else {
          targetEl.value = targetVal;
          targetEl.focus();
        }
      });
    });

    // Claim submit
    $('#claimForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const reportId = e.currentTarget.dataset.reportId;
      if (!reportId) return;

      const btn = $('#claimBtn');
      btn.disabled = true;

      // Extract harness value
      let harness = null;
      if (harnessSelect) {
        if (harnessSelect.value === 'custom') {
          harness = (harnessCustom && harnessCustom.value.trim()) || null;
        } else {
          harness = harnessSelect.value || null;
        }
      }

      // Extract model value
      let model = null;
      if (modelSelect) {
        if (modelSelect.value === 'custom') {
          model = (modelCustom && modelCustom.value.trim()) || null;
        } else {
          model = modelSelect.value || null;
        }
      }

      const payload = {
        reportId,
        builderKind: $('#kind').value || 'unknown',
        builderName: $('#builderName').value.trim() || null,
        platform: $('#platform').value || null,
        harness,
        model,
      };

      try {
        const res = await fetch('/api/leaderboard/claim', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Oddaja trditve ni uspela');
        renderVerdict(data);
        loadBoard();
      } catch (err) {
        renderVerdict({ verification: 'unverified', evidence: [err.message] });
      } finally {
        btn.disabled = false;
      }
    });
  }

  function renderVerdict(data) {
    const box = $('#verdict');
    box.hidden = false;
    box.className = 'verdict-banner ' + (data.verification || 'unverified');
    box.textContent = '';

    box.appendChild(el('strong', '', t(data.verification || 'unverified')));
    box.appendChild(el('div', '', t((data.verification || 'unverified') + 'Help')));

    if (data.stackHint && data.stackHint.level !== 'none') {
      box.appendChild(el('div', 'field-note', t('harnessNote')));
    }

    const contradictions = (data.contradictions || []).slice(0, 4);
    if (contradictions.length) {
      box.appendChild(el('div', 'claim-tools-text contradiction-header', t('contradictionsTitle')));
      const ul = el('ul', 'contradiction-list');
      for (const c of contradictions) ul.appendChild(el('li', '', c));
      box.appendChild(ul);
    }

    const notes = (data.evidence || []).slice(0, 6);
    if (notes.length) {
      box.appendChild(el('div', 'claim-tools-text', t('evidenceTitle')));
      const ul = el('ul');
      for (const n of notes) ul.appendChild(el('li', '', n));
      box.appendChild(ul);
    }
  }

  /* ---------------- Site Inspection Drawer ---------------- */

  async function openSiteDrawer(host) {
    state.activeSite = host;
    $$('.floating-site-card').forEach((c) => {
      c.classList.toggle('expanded', c.dataset.host === host);
    });
  }

  function closeSiteDrawer() {
    state.activeSite = null;
    const drawer = $('#siteDrawer');
    const backdrop = $('#drawerBackdrop');
    if (drawer) {
      drawer.classList.remove('open');
      drawer.setAttribute('aria-hidden', 'true');
    }
    if (backdrop) backdrop.hidden = true;

    // Clean URL query param
    const url = new URL(location);
    url.searchParams.delete('site');
    history.replaceState(null, '', url);
  }

  function populateSiteDrawer(data) {
    const scans = data.scans || [];
    const latest = scans[0] || {};

    $('#drawerScore').textContent = String(latest.score || '—');
    $('#drawerGrade').textContent = latest.grade || '—';
    $('#drawerGrade').className = 'score-grade grade-pill ' + (latest.grade || 'C');

    const drawerRel = $('#drawerReliability');
    if (drawerRel) {
      drawerRel.textContent = '';
      const latestDeg = normalizeDegradedInfo(latest);
      if (latestDeg) {
        const relNode = buildReliabilityBadge(latestDeg, 'tip-drawer-latest');
        if (relNode) drawerRel.appendChild(relNode);
        drawerRel.hidden = false;
      } else {
        drawerRel.hidden = true;
      }
    }

    $('#drawerLastScan').textContent = latest.at
      ? new Date(latest.at).toLocaleString(window.i18n.lang() === 'sl' ? 'sl-SI' : 'en-GB')
      : '—';
    $('#drawerScanCount').textContent = String(scans.length);

    // Domain bars
    const bars = $('#drawerDomainBars');
    bars.textContent = '';
    const domainKeys = ['sec', 'comp', 'perf', 'a11y', 'seo', 'quality'];
    const domainKeyMap = {
      sec: 'security',
      comp: 'compliance',
      perf: 'performance',
      a11y: 'accessibility',
      seo: 'seo',
      quality: 'quality',
    };

    domainKeys.forEach((k) => {
      const val = latest[k];
      if (val === undefined || val === null) return;
      const box = el('div', 'domain-bar-item');
      const meta = el('div', 'bar-meta');
      meta.appendChild(el('span', '', getDomainLabel(domainKeyMap[k] || k)));
      meta.appendChild(el('span', 'bar-score', String(val)));
      box.appendChild(meta);

      const track = el('div', 'bar-track');
      const fill = el('div', 'bar-fill' + (val < 55 ? ' low' : val < 75 ? ' medium' : ''));
      fill.style.width = Math.max(0, Math.min(100, val)) + '%';
      track.appendChild(fill);
      box.appendChild(track);
      bars.appendChild(box);
    });

    // Claim info
    const claimCard = $('#drawerClaimCard');
    claimCard.textContent = '';
    const subs = data.submissions || [];
    if (!subs.length) {
      claimCard.appendChild(el('div', 'field-note', t('noClaimYet')));
    } else {
      const sub = subs[0];
      const wrap = el('div', 'claim-cell-wrap');
      const badge = el('span', 'badge-status ' + sub.verification, t(sub.verification));
      wrap.appendChild(badge);

      if (window.BRAND_ICONS) {
        const cluster = document.createElement('div');
        cluster.innerHTML = window.BRAND_ICONS.renderClaimBadge(sub);
        wrap.appendChild(cluster.firstElementChild || cluster);
      } else {
        if (sub.builderName) wrap.appendChild(el('div', 'claim-title', sub.builderName));
        if (sub.platform) wrap.appendChild(el('div', 'tag-platform', sub.platform));
        const tools = [sub.harness, sub.model].filter(Boolean).join(' / ');
        if (tools) wrap.appendChild(el('div', 'claim-tools-text', tools));
      }

      if (sub.evidence && sub.evidence.length) {
        const evList = el('ul', 'field-note');
        sub.evidence.slice(0, 4).forEach((ev) => evList.appendChild(el('li', '', ev)));
        wrap.appendChild(evList);
      }
      claimCard.appendChild(wrap);
    }

    // Score History
    const histList = $('#drawerHistoryList');
    histList.textContent = '';
    scans.slice(0, 10).forEach((s, idx) => {
      const row = el('div', 'history-item');
      row.appendChild(el('span', '', new Date(s.at).toLocaleDateString()));
      const hDeg = normalizeDegradedInfo(s);
      if (hDeg) {
        const tag = hDeg.kind === 'waf' ? 'WAF' : hDeg.kind === 'render' ? 'Partial' : 'Incomplete';
        row.appendChild(el('span', 'history-degraded-tag', `${tag} · ≤${hDeg.scoreCap}`));
      }
      row.appendChild(el('span', 'score-num-val', String(s.score)));
      row.appendChild(el('span', 'grade-pill ' + s.grade, s.grade));
      histList.appendChild(row);
    });
    wireHintTooltips($('#siteDrawer'));

    // Action handlers
    $('#drawerRescanBtn').onclick = () => {
      closeSiteDrawer();
      $('#urlInput').value = data.host;
      $('#scanForm').dispatchEvent(new Event('submit', { cancelable: true }));
    };

    $('#drawerRemovalBtn').onclick = () => {
      $('#removalSiteHost').value = data.host;
      $('#removalModal').showModal();
    };
  }

  function initDrawer() {
    $('#drawerClose').addEventListener('click', closeSiteDrawer);
    $('#drawerBackdrop').addEventListener('click', closeSiteDrawer);

    // Modal handlers
    $('#modalCancelBtn').addEventListener('click', () => $('#removalModal').close());
    $('#removalForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const host = $('#removalSiteHost').value.trim();
      if (!host) return;

      try {
        const res = await fetch('/api/leaderboard/removal', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host }),
        });
        const data = await res.json();
        if (res.ok) {
          alert(data.message || t('removalSent'));
          $('#removalModal').close();
          closeSiteDrawer();
          loadBoard();
        } else {
          alert(data.error || (window.i18n.lang() === 'sl' ? 'Napaka pri odstranitvi domene' : 'Error removing domain'));
        }
      } catch (err) {
        alert(t('networkError') || (window.i18n.lang() === 'sl' ? 'Napaka pri povezavi s strežnikom' : 'Server connection error'));
      }
    });

    // In-table search input
    $('#tableSearch').addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      renderBoard();
    });
  }

  function initNavLinks() {
    $$('a[data-view]').forEach((link) => {
      link.addEventListener('click', (e) => {
        let v = link.dataset.view;
        if (COHORT_VIEWS.has(v)) {
          state.creatorCohort = v;
          v = 'creators';
        }
        if (v === 'worst') v = 'slop';
        if (VIEWS.includes(v)) {
          e.preventDefault();
          state.view = v;
          const url = new URL(location);
          if (v === 'top') {
            url.searchParams.delete('view');
            url.searchParams.delete('cohort');
          } else {
            url.searchParams.set('view', v);
            if (v === 'creators') url.searchParams.set('cohort', state.creatorCohort || 'agency');
            else url.searchParams.delete('cohort');
          }
          history.replaceState(null, '', url);
          buildTabs();
          updateSubrows();
          loadBoard();
          document.getElementById('board').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    });

    // Mobile nav toggle
    const navToggle = $('#navToggle');
    const navDrawer = $('#mobileNavDrawer');
    if (navToggle && navDrawer) {
      navToggle.addEventListener('click', () => {
        navDrawer.hidden = !navDrawer.hidden;
      });
      $$('#mobileNavDrawer a').forEach((a) => {
        a.addEventListener('click', () => {
          navDrawer.hidden = true;
        });
      });
    }

    // Footer removal button
    const footerRemoval = $('#footerRemovalBtn');
    if (footerRemoval) {
      footerRemoval.addEventListener('click', () => {
        $('#removalSiteHost').value = '';
        $('#removalModal').showModal();
      });
    }
  }

  /* ---------------- Boot ---------------- */

  function boot() {
    const params = new URLSearchParams(location.search);
    const viewParam = params.get('view');
    const cohortParam = params.get('cohort');

    if (COHORT_VIEWS.has(viewParam)) {
      state.view = 'creators';
      state.creatorCohort = viewParam;
    } else if (viewParam === 'creators') {
      state.view = 'creators';
      if (cohortParam && COHORT_VIEWS.has(cohortParam)) {
        state.creatorCohort = cohortParam;
      } else {
        state.creatorCohort = 'agency';
      }
    } else if (viewParam === 'worst') {
      state.view = 'slop';
    } else if (viewParam === 'disputed') {
      state.view = 'top';
    } else if (VIEWS.includes(viewParam)) {
      state.view = viewParam;
    }

    initTheme();
    initHintTooltipRuntime();
    initScope();
    initNavLinks();
    initSubmitForm();
    initClaimForm();
    initDrawer();
    applyStaticText();
    loadBoard();

    const siteParam = params.get('site');
    if (siteParam) {
      openSiteDrawer(siteParam);
    }
  }

  window.renderResult = renderResult;
  window.renderLowLevelTelemetry = renderLowLevelTelemetry;

  /* ---------------- AI Fix Prompt Generation & Clipboard Helpers ---------------- */

  function buildSingleAiPrompt(report, f) {
    const host = cleanDisplayHost(report.finalUrl || report.target || 'my-website.com');
    return [
      `I am fixing the following finding reported by VibeScan on ${host}:`,
      ``,
      `Title: ${f.title}`,
      `Severity: ${(f.severity || 'low').toUpperCase()}`,
      `Category: ${f.domain || 'general'}`,
      `Issue: ${f.whatItIs || f.detail || ''}`,
      f.impact ? `Impact: ${f.impact}` : '',
      f.worstCase ? `Worst Case: ${f.worstCase}` : '',
      f.evidence ? `Observed Evidence:\n${f.evidence}` : '',
      `Recommended Fix: ${f.fix || ''}`,
      ``,
      `Please provide the exact code changes or configuration directives to remediate this finding.`
    ].filter(Boolean).join('\n');
  }

  function buildFullAiPrompt(report, findings) {
    const host = cleanDisplayHost(report.finalUrl || report.target || 'my-website.com');
    const lines = [
      `# VibeScan Remediation Plan for ${host}`,
      `Overall Score: ${report.score}/100 (Grade: ${report.grade || 'C'})`,
      `Generated: ${new Date().toISOString()}`,
      ``,
      `Please review and implement the following fixes across my codebase and infrastructure:`,
      ``
    ];
    const actionable = (findings || []).filter((f) => f.severity !== 'info');
    const items = actionable.length ? actionable : findings;
    items.forEach((f, idx) => {
      lines.push(`### ${idx + 1}. [${(f.severity || 'low').toUpperCase()}] ${f.title}`);
      lines.push(`- Category: ${f.domain || 'general'}`);
      lines.push(`- Problem: ${f.whatItIs || f.detail || ''}`);
      if (f.evidence) lines.push(`- Evidence: ${f.evidence}`);
      if (f.fix) lines.push(`- Recommended Fix: ${f.fix}`);
      lines.push(``);
    });
    lines.push(`Provide the necessary code modifications, configuration changes (e.g. Caddy, Nginx, Cloudflare, headers, or framework settings), and verification commands.`);
    return lines.join('\n');
  }

  function copyToClipboard(text, btn, successText) {
    const span = btn ? btn.querySelector('span') : null;
    const origText = span ? span.textContent : '';
    const onDone = () => {
      if (span) span.textContent = successText;
      if (btn) btn.classList.add('copied');
      setTimeout(() => {
        if (span) span.textContent = origText;
        if (btn) btn.classList.remove('copied');
      }, 2000);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onDone).catch(() => {
        fallbackCopy(text);
        onDone();
      });
    } else {
      fallbackCopy(text);
      onDone();
    }
  }

  function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }

  boot();
})();
