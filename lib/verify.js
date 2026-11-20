'use strict';
/**
 * VibeScan provenance verification engine.
 *
 * WHAT THIS DOES
 *   Takes a self-reported provenance claim (builder kind, builder name,
 *   platform, harness, model) plus `report.meta.build` — the compact
 *   fingerprint collected by lib/buildfp.js — and returns how much of that
 *   claim the scanner can actually evidence.
 *
 * HARD RULE (PLAN-LEADERBOARD.md §4.2, operator-confirmed 2026-10-22)
 *   `harness` and `model` are NEVER `verified`. A model cannot be inferred from
 *   rendered output; pretending otherwise would make the whole leaderboard
 *   worthless. They are stored and displayed, and the strongest statement this
 *   module makes is a grey-text `stackHint` ("matches observed stack").
 *
 *   Verifiable: builder_kind, builder_name, platform.
 *
 * DESIGN
 *   Every signal is a pure function returning { weight, say } or null, so the
 *   weights live in one table and can be re-tuned without touching logic.
 *   Verification is conservative by construction: a wrong `verified` costs far
 *   more than a missing one, so the threshold is high and a decisive
 *   contradiction downgrades to `disputed` instead of being averaged away.
 */

const VERIFY_THRESHOLD = 55;

/* ------------------------------------------------------------------ *
 * Text helpers
 * ------------------------------------------------------------------ */

function lc(v) {
  return String(v || '').toLowerCase();
}

function tokens(s) {
  return lc(s)
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .split(' ')
    .filter((t) => t.length > 1);
}

/**
 * Fuzzy name match by token overlap. Substring matching is deliberately NOT
 * used: "Studio" would match every agency on earth.
 *
 * Two ways to pass:
 *   1. Every claimed token appears in the observed text AND at least one of
 *      them is distinctive (>= 5 chars). This is the normal case:
 *      "Acme" inside "Acme Studio LLC" — a legal suffix on the site
 *      does not make the claim wrong.
 *   2. Otherwise, symmetric overlap must be high, so a single shared generic
 *      word ("Studio") never credits the wrong agency.
 */
function nameOverlap(claimed, observed) {
  const a = new Set(tokens(claimed));
  const b = new Set(tokens(observed));
  if (!a.size || !b.size) return 0;

  let hit = 0;
  const matched = [];
  for (const t of a) {
    if (b.has(t)) {
      hit++;
      matched.push(t);
    }
  }
  const distinctive = matched.filter((t) => t.length >= 5);
  if (hit === a.size && distinctive.length) return 1; // full claimed name present

  const min = Math.min(hit / a.size, hit / b.size);
  const bonus = distinctive.length ? Math.min(0.2, distinctive.length * 0.1) : 0;
  return Math.min(1, min + bonus);
}

/* ------------------------------------------------------------------ *
 * AI-artefact signals
 *
 * Split into DECISIVE (an explicit build badge, or an exposed agent file: the
 * author is either telling us or leaving their tools in the repo) and WEAK
 * (style, copy, library choices — all reproducible by a human, all fakeable).
 * Only DECISIVE evidence may contradict a hand-built claim.
 * ------------------------------------------------------------------ */

const DECISIVE_AI = [
  { id: 'v0', weight: 90, key: 'v0Badge', say: 'Page carries a v0.dev build badge.' },
  { id: 'lovable', weight: 90, key: 'lovableBadge', say: 'Page carries a Lovable build badge.' },
  { id: 'bolt', weight: 90, key: 'boltBadge', say: 'Page carries a Bolt build badge.' },
  { id: 'replit', weight: 90, key: 'replitBadge', say: 'Page carries a Replit build badge/link.' },
  { id: 'marblism', weight: 90, key: 'marblismBadge', say: 'Page carries a Marblism build badge.' },
  { id: 'create-xyz', weight: 90, key: 'createXyzBadge', say: 'Page carries a Create.xyz signature.' },
];

const AGENT_FILE_WEIGHT = 85;

const WEAK_AI = [
  { id: 'shadcn', weight: 14, key: 'shadcn', say: 'Markup follows shadcn/ui component conventions.' },
  { id: 'tailwind4', weight: 10, key: 'tailwind4', say: 'Tailwind utility classes are present.' },
  { id: 'lucide', weight: 8, key: 'lucide', say: 'Icons come from lucide, a common scaffold default.' },
  { id: 'app-router', weight: 6, key: 'appRouter', say: 'Build output is a Next.js App Router layout.' },
];

const AI_PHRASE_WEIGHT = 4; // per distinct phrase
const AI_PHRASE_CAP = 12;

/**
 * A self-disclosure ("zgrajeno s strojem", "built with AI") is the author's own
 * statement, so it is strong enough to SUPPORT an `ai` claim. It is kept out of
 * the contradiction bucket on purpose: a studio may use AI for one section and
 * still legitimately call the site agency-built, so a disclosure must never
 * mark an `agency`/`solo` claim as disputed.
 */
const SELF_DISCLOSURE_WEIGHT = 60;

/**
 * Legal/structural tokens that make a builder credit read as a company.
 * Note the missing trailing \b after the dotted abbreviations: "d.o.o." ends
 * on a non-word character, so a word boundary would never match there.
 */
const COMPANY_TOKEN =
  /\b(?:d\.?\s?o\.?\s?o|s\.?\s?p|ltd|llc|inc|gmbh|studio|agency|agencija|digital|group|collective)\b/i;

/**
 * Generic infrastructure tokens that should not trigger builder name matches on their own.
 */
const GENERIC_INFRA_TOKENS = new Set([
  'static', 'assets', 'media', 'cdn', 'cloud', 'server', 'origin',
  'edge', 'host', 'hosting', 'serv', 'service', 'services', 'infra',
  'app', 'apps', 'web', 'site', 'node', 'cluster', 'data', 'store',
  'shop', 'prod', 'production', 'dev', 'test', 'stage', 'staging',
  'api', 'apis', 'auth', 'login', 'portal', 'mail', 'email', 'dns',
  'mage', 'www', 'analytics', 'tagmanager', 'gtag', 'facebook',
  'meta', 'clarity', 'hotjar', 'sentry', 'doubleclick', 'google',
  'googletagmanager'
]);

/* ------------------------------------------------------------------ *
 * Fingerprint access (defensive: any field may be missing)
 * ------------------------------------------------------------------ */

function build(report) {
  const meta = (report && report.meta) || {};
  return meta.build || {};
}

function flags(fp) {
  const f = fp.flags || {};
  return {
    shadcn: Boolean(f.shadcn),
    tailwind4: Boolean(f.tailwind4),
    lucide: Boolean(f.lucide),
    appRouter: Boolean(f.appRouter),
    v0Badge: Boolean(f.v0Badge),
    lovableBadge: Boolean(f.lovableBadge),
    boltBadge: Boolean(f.boltBadge),
    replitBadge: Boolean(f.replitBadge),
    marblismBadge: Boolean(f.marblismBadge),
    createXyzBadge: Boolean(f.createXyzBadge),
    selfDeclaredAI: Boolean(f.selfDeclaredAI),
  };
}

/**
 * Sum the AI evidence for a fingerprint.
 * @returns {{ decisive:number, weak:number, total:number, evidence:string[], ids:string[] }}
 */
function aiEvidence(fp) {
  const f = flags(fp);
  const evidence = [];
  const ids = [];
  let decisive = 0;
  let weak = 0;

  // A self-disclosure is the author's own statement, so it is strong support
  // for an "ai" claim — but it is reported in its own bucket so it can never
  // contradict an agency/solo claim (see SELF_DISCLOSURE_WEIGHT).
  if (f.selfDeclaredAI) {
    evidence.push('Page explicitly discloses that it was built with AI.');
    ids.push('self-disclosed');
  }

  for (const sig of DECISIVE_AI) {
    if (f[sig.key]) {
      decisive += sig.weight;
      evidence.push(sig.say);
      ids.push(sig.id);
    }
  }

  const agentFiles = Array.isArray(fp.agentFiles) ? fp.agentFiles : [];
  if (agentFiles.length) {
    decisive += AGENT_FILE_WEIGHT;
    evidence.push(`Agent instruction file is publicly reachable (${agentFiles.join(', ')}).`);
    ids.push('agent-files');
  }

  for (const sig of WEAK_AI) {
    if (f[sig.key]) {
      weak += sig.weight;
      evidence.push(sig.say);
      ids.push(sig.id);
    }
  }

  const phrases = Array.isArray(fp.aiPhrases) ? fp.aiPhrases.slice(0, 3) : [];
  if (phrases.length) {
    weak += Math.min(AI_PHRASE_CAP, phrases.length * AI_PHRASE_WEIGHT);
    evidence.push(
      `Copy uses phrases over-represented in generated sites (${phrases.join(', ')}).`
    );
    ids.push('ai-copy');
  }

  const disclosure = f.selfDeclaredAI ? SELF_DISCLOSURE_WEIGHT : 0;

  return {
    decisive,
    weak,
    disclosure,
    total: Math.min(95, decisive + weak + disclosure),
    // Support for an "ai" claim (badges, agent files, disclosure).
    supportsAI: Math.min(95, decisive + disclosure),
    evidence,
    ids,
  };
}

/* ------------------------------------------------------------------ *
 * Builder-name evidence
 * ------------------------------------------------------------------ */

/**
 * @returns {{weight:number, evidence:string, context:string}|null}
 *   `context` is the matched source text, so callers can inspect how the
 *   builder is described (company form vs personal name) without another pass.
 */
function builderNameSignal(claimed, fp) {
  const surfaces = [
    ['footer text', fp.footerText],
    ['humans.txt', fp.humansTxt],
    ['og:site_name', fp.ogSiteName],
  ];
  for (const [where, context] of surfaces) {
    if (!context) continue;
    if (nameOverlap(claimed, context) >= 0.7) {
      return { weight: 85, evidence: `Builder name appears in the ${where}.`, context };
    }
  }
  const names = Array.isArray(fp.jsonLdNames) ? fp.jsonLdNames : [];
  for (const n of names) {
    if (nameOverlap(claimed, n) >= 0.7) {
      return {
        weight: 85,
        evidence: 'Builder name matches schema.org structured data.',
        context: n,
      };
    }
  }

  // Infrastructure / CSP / asset hostname check
  const infraCandidates = [];
  if (Array.isArray(fp.cspHosts)) infraCandidates.push(...fp.cspHosts);
  if (Array.isArray(fp.assetHosts)) infraCandidates.push(...fp.assetHosts);
  if (Array.isArray(fp.assets)) infraCandidates.push(...fp.assets);

  const distinctiveClaimed = tokens(claimed).filter(
    (t) => t.length >= 4 && !COMPANY_TOKEN.test(t) && !GENERIC_INFRA_TOKENS.has(t)
  );

  if (distinctiveClaimed.length > 0) {
    for (const item of infraCandidates) {
      if (!item || typeof item !== 'string') continue;
      const itemLower = lc(item);
      const itemTokens = new Set(tokens(itemLower));

      const matched = distinctiveClaimed.some(
        (t) => itemTokens.has(t) || (t.length >= 5 && itemLower.includes(t))
      );

      if (matched) {
        return {
          weight: 85,
          evidence: 'Builder name matches asset/infrastructure hostname in CSP or scripts.',
          context: item,
          isInfra: true,
        };
      }
    }
  }

  return null;
}

/* ------------------------------------------------------------------ *
 * Public API
 * ------------------------------------------------------------------ */

/**
 * Verify one provenance claim.
 *
 * @param {object} claim  { builderKind, builderName, platform, harness, model }
 * @param {object} report full VibeScan report (only `meta.build` is read)
 * @returns {{
 *   verification: 'verified'|'disputed'|'unverified',
 *   confidence: number,
 *   evidence: string[],
 *   contradictions: string[],
 *   platform: string|null,
 *   stackHint: { level:'none'|'weak-ai'|'likely-ai', signals:string[] },
 *   verifiableFields: string[]
 * }}
 */
function verifyClaim(claim, report) {
  const fp = build(report);
  const evidence = [];
  const contradictions = [];

  const detectedPlatform = fp.platform || null;
  const claimedPlatform = lc(claim && claim.platform);
  /** @type {Record<string,{status:string, confidence:number}>} */
  const fields = {};

  // ---- 1. Platform: deterministic. Evidence is confined to its own field so
  //         it cannot inflate an unrelated claim (a WordPress fingerprint must
  //         not "verify" a builder-name claim). ----
  const CUSTOM_FRAMEWORKS = new Set(['nextjs', 'nuxt', 'astro']);
  const PROPRIETARY_CMS = new Set(['wordpress', 'shopify', 'wix', 'squarespace', 'webflow']);

  if (claimedPlatform) {
    if (!detectedPlatform) {
      if (claimedPlatform === 'custom') {
        fields.platform = { status: 'unverified', confidence: 40 };
        evidence.push('No proprietary CMS detected; consistent with custom code.');
      } else {
        fields.platform = { status: 'unverified', confidence: 0 };
        evidence.push('No platform fingerprint could be established.');
      }
    } else if (claimedPlatform === detectedPlatform) {
      fields.platform = { status: 'verified', confidence: 95 };
      evidence.push(`Platform fingerprint matches the claim: ${detectedPlatform}.`);
    } else if (claimedPlatform === 'custom' && CUSTOM_FRAMEWORKS.has(detectedPlatform)) {
      // Frameworks like Next.js, Nuxt and Astro are custom-coded frameworks, not CMSs.
      fields.platform = { status: 'verified', confidence: 90 };
      evidence.push(`Platform fingerprint consistent with custom code (${detectedPlatform}).`);
    } else if (claimedPlatform === 'custom' && !PROPRIETARY_CMS.has(detectedPlatform)) {
      fields.platform = { status: 'verified', confidence: 80 };
      evidence.push(`Custom build verified: no proprietary CMS detected (${detectedPlatform}).`);
    } else {
      fields.platform = { status: 'disputed', confidence: 95 };
      contradictions.push(
        `Claimed platform "${claimedPlatform}" but the page fingerprints as ${detectedPlatform}.`
      );
    }
  } else if (detectedPlatform) {
    evidence.push(`Platform fingerprint (not claimed): ${detectedPlatform}.`);
  }

  // ---- 2. Builder name (computed first: it is also evidence for the kind). ----
  const nameSig = claim && claim.builderName ? builderNameSignal(claim.builderName, fp) : null;
  if (claim && claim.builderName) {
    if (nameSig) {
      fields.builderName = { status: 'verified', confidence: nameSig.weight };
      evidence.push(nameSig.evidence);
    } else {
      fields.builderName = { status: 'unverified', confidence: 0 };
      evidence.push(
        'No builder credit found in the footer, humans.txt or structured data — name unverified.'
      );
    }
  }

  // ---- 3. Builder kind vs AI evidence and builder credit. ----
  const ai = aiEvidence(fp);
  const kind = lc(claim && claim.builderKind) || 'unknown';

  if (kind !== 'unknown') {
    if (kind === 'ai') {
      // total includes the weak style signals, so a self-disclosure plus any
      // scaffolding evidence is enough; style alone still is not.
      if (ai.total >= VERIFY_THRESHOLD) {
        fields.builderKind = { status: 'verified', confidence: ai.total };
        evidence.push(...ai.evidence);
      } else {
        fields.builderKind = { status: 'unverified', confidence: ai.total };
        evidence.push(...ai.evidence);
        evidence.push(
          ai.weak > 0
            ? 'Observed stack (modern scaffolding) is consistent with AI-assisted build; claim recorded.'
            : 'No explicit AI build badge observed; claim recorded.'
        );
      }
    } else if (ai.decisive > 0) {
      // Only decisive evidence (a build badge, an exposed agent file) may
      // contradict a human claim. shadcn + Tailwind is what humans ship in 2026.
      fields.builderKind = { status: 'disputed', confidence: ai.decisive };
      contradictions.push(
        'The page carries explicit AI build artefacts, which contradict a hand-built claim.'
      );
      evidence.push(...ai.evidence.slice(0, 3));
    } else if (nameSig && (kind === 'agency' || kind === 'solo')) {
      // A credited builder IS the evidence for "an agency/studio built this".
      // The distinction between agency and solo is inferred from how the credit
      // reads: a company form ("d.o.o.", "LLC", "Studio", "Agency") supports
      // agency, a bare personal name does not contradict solo.
      const companyLike =
        COMPANY_TOKEN.test(claim.builderName || '') ||
        COMPANY_TOKEN.test(nameSig.context || '') ||
        Boolean(nameSig.isInfra);
      if (kind === 'agency' && companyLike) {
        fields.builderKind = { status: 'verified', confidence: 80 };
        evidence.push('Builder credit reads as a company, consistent with an agency claim.');
      } else if (kind === 'solo') {
        fields.builderKind = { status: 'verified', confidence: 75 };
        evidence.push('A credited individual builder is consistent with a solo claim.');
      } else {
        fields.builderKind = { status: 'unverified', confidence: 60 };
        evidence.push('Builder credit found, but it does not distinguish agency from solo.');
      }
    } else {
      fields.builderKind = { status: 'unverified', confidence: 40 };
      evidence.push('No explicit AI build artefacts found; a hand-built claim cannot be disproven.');
    }
  }

  // ---- 4. Headline verdict. ----
  // Any contradiction dominates. Otherwise every claimed verifiable field must
  // be verified for the submission to carry the badge; a partially-supported
  // claim is shown as unverified rather than being rounded up, because the
  // badge is the only thing worth earning here.
  const statuses = Object.values(fields).map((f) => f.status);
  const claimedCount = statuses.length;
  let verification;
  if (statuses.includes('disputed')) verification = 'disputed';
  else if (claimedCount > 0 && statuses.every((s) => s === 'verified')) verification = 'verified';
  else verification = 'unverified';

  // Headline confidence describes the *weakest* claimed field: a chain of
  // claims is only as strong as its weakest link.
  const confidence = claimedCount
    ? Math.min(...Object.values(fields).map((f) => f.confidence))
    : ai.total;

  // ---- 5. Harness / model: advisory only, never verified. ----
  const stackHint =
    ai.supportsAI >= VERIFY_THRESHOLD
      ? { level: 'likely-ai', signals: ai.evidence.slice(0, 4) }
      : ai.total >= 25
        ? { level: 'weak-ai', signals: ai.evidence.slice(0, 4) }
        : { level: 'none', signals: [] };

  return {
    verification,
    confidence,
    fields,
    evidence,
    contradictions,
    platform: detectedPlatform,
    stackHint,
    // Explicit, so a future contributor cannot "just add" harness verification
    // without editing this list and the operator decision it encodes.
    verifiableFields: ['builderKind', 'builderName', 'platform'],
  };
}

module.exports = {
  verifyClaim,
  nameOverlap,
  aiEvidence,
  VERIFY_THRESHOLD,
  WEAK_AI,
  DECISIVE_AI,
  AGENT_FILE_WEIGHT,
};
