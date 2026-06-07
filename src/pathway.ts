// src/pathway.ts
//
// Composite-pathway recompute — the D4 reference implementation.
//
// Determinism contract — DO NOT change without coordinating with the source.
// The classification, the (r_strategy, loop_type) ordering, and the kg-basis
// aggregation below are lifted byte-for-byte from:
//
//   aueruditus/CirculrDesignerGA
//     supabase/functions/_shared/mca/pathwayTaxonomy.ts   (taxonomy + sort + D10 normalisation)
//     supabase/functions/_shared/mca/pathwayBreakdown.ts  (aggregatePathwayBreakdown, kg-basis)
//     supabase/functions/publish-to-passport/computationManifest.ts (aggregatePathwayOutputs, PathwayOutput)
//   source commit: 4d904b14 ("feat(pathways): add signed pathway_outputs[] block
//                             to computation manifest (P5a)")
//
// These MUST stay byte-equivalent to the producer on classification + ordering +
// aggregation. Drift = the verifier reproduces a different block than the
// producer signed → false MISMATCH(pathway_recomputation) on real prod manifests.
// The single comparator `compareComposite` is the source of truth for the §5.4
// sort across three surfaces (producer, this CLI, passport); a coarse sort on
// r_strategy alone ties the two R11 loop types and reintroduces the §5.4 R4
// determinism break.
//
// D4 (co-design): this module is the SINGLE reference implementation. The
// passport `verify_computation` tool (SPEC B Phase 2) lifts it UNMODIFIED — the
// same relationship src/crypto.ts has with the producer's manifest primitives.
// Keep it free of CLI-only concerns (no chalk, no commander, no process) so the
// lift stays clean (AC6).
//
// `roundHalfEven` is imported from crypto.ts — the one shared primitive the
// producer's aggregatePathwayOutputs also uses; in a lift, it resolves to the
// host module's own crypto, exactly as today.

import { roundHalfEven } from './crypto.js';

// =============================================================================
// §2 — Canonical 12-strategy R-ladder (lifted from pathwayTaxonomy.ts)
// =============================================================================

export type CanonicalRStrategy =
  | 'R1' | 'R2' | 'R3' | 'R4' | 'R5' | 'R6'
  | 'R7' | 'R8' | 'R9' | 'R10' | 'R11' | 'R12';

/** Canonical display name per R-code (REFERENCE §2 — CirculR v1.5.0 hierarchy). */
export const CANONICAL_R_STRATEGY: Record<CanonicalRStrategy, string> = {
  R1: 'Refuse',
  R2: 'Reduce',
  R3: 'Rethink',
  R4: 'Redesign',
  R5: 'Reuse',
  R6: 'Repair',
  R7: 'Refurbish',
  R8: 'Remanufacture',
  R9: 'Repurpose',
  R10: 'Re-earth',
  R11: 'Recycle',
  R12: 'Recover',
};

// =============================================================================
// §4 — Loop-type axis (value-retention tier, orthogonal to R-strategy)
// =============================================================================

/**
 * `open_loop_functional` is RESERVED per REFERENCE §4 — defined on the axis but
 * not yet emitted by any classified pathway.
 */
export type LoopType =
  | 'reuse'
  | 'closed_loop'
  | 'open_loop_downcycle'
  | 'open_loop_functional';

// =============================================================================
// D10 — normalise stored enhanced_transactions.r_strategy onto a canonical code
// =============================================================================

/** Strategy display name (separator-free, lowercase) → canonical R-code. */
const STRATEGY_NAME_TO_CODE: Record<string, CanonicalRStrategy> = {
  refuse: 'R1',
  reduce: 'R2',
  rethink: 'R3',
  redesign: 'R4',
  reuse: 'R5',
  repair: 'R6',
  refurbish: 'R7',
  remanufacture: 'R8',
  repurpose: 'R9',
  reearth: 'R10',
  recycle: 'R11',
  recover: 'R12',
};

/**
 * Reconcile a stored `enhanced_transactions.r_strategy` value onto a canonical
 * R-code (spec §0c D10). The strategy NAME is reliable; the numeric prefix is
 * NOT, so it is stripped and discarded. A bare, already-canonical code
 * (`R1`..`R12`) is honoured directly. Returns `null` for null/blank input or an
 * unrecognised strategy name.
 */
export function normaliseStoredRStrategy(
  stored: string | null | undefined,
): CanonicalRStrategy | null {
  if (!stored) return null;
  const raw = stored.trim();
  if (!raw) return null;

  // Forward path: accept an already-canonical bare code (case-insensitive).
  const bare = raw.toUpperCase().match(/^R(\d{1,2})$/);
  if (bare) {
    const n = Number(bare[1]);
    if (n >= 1 && n <= 12) return (`R${n}`) as CanonicalRStrategy;
  }

  // Legacy path: discard the unreliable "r<n>_" prefix, reconcile on the name.
  const name = raw
    .toLowerCase()
    .replace(/^r\d+[_-]?/, '')
    .replace(/[_\-\s]/g, '');
  return STRATEGY_NAME_TO_CODE[name] ?? null;
}

// =============================================================================
// Composite key + canonical deterministic ordering (the §5.4 SSOT sort)
// =============================================================================

export type CompositeKey = string; // `${CanonicalRStrategy}|${LoopType}`

/** Stable composite key for keying a (R-strategy, loop_type) breakdown. */
export function compositeKey(r: string, loop: string): CompositeKey {
  return `${r}|${loop}`;
}

/**
 * Canonical deterministic ordering for the manifest `pathway_outputs[]` block
 * (spec §5.4): R-strategy by NUMERIC value ascending (so R2 precedes R10 — NOT
 * lexicographic), then loop_type lexicographic ascending. This comparator is the
 * single source of truth for that sort; consumers must not re-implement it
 * inline.
 */
export function compareComposite(
  a: { rStrategy: string; loopType: string },
  b: { rStrategy: string; loopType: string },
): number {
  const an = Number(a.rStrategy.slice(1));
  const bn = Number(b.rStrategy.slice(1));
  if (an !== bn) return an - bn;
  if (a.loopType < b.loopType) return -1;
  if (a.loopType > b.loopType) return 1;
  return 0;
}

// =============================================================================
// PathwayOutput — the signed block entry shape (lifted from computationManifest.ts)
// =============================================================================

export interface PathwayOutput {
  /** Canonical R-code, e.g. "R5", "R11". */
  r_strategy: string;
  /** "reuse" | "closed_loop" | "open_loop_downcycle" (open_loop_functional reserved). */
  loop_type: string;
  /** Count of recovery legs in this (r_strategy, loop_type) pathway. */
  events: number;
  /** Summed quantity_kg for this pathway, roundHalfEven(_, 4). */
  kg: number;
  /** kg / total kg across all pathways, roundHalfEven(_, 4). Rates sum to 1.0 (±0.001) when any kg > 0. */
  rate: number;
}

// =============================================================================
// Pure reducer (lifted from pathwayBreakdown.ts, kg-basis path)
// =============================================================================

/** A single classified recovery item fed into the aggregator. */
export interface ClassifiedPathwayItem {
  rStrategy: CanonicalRStrategy;
  loopType: LoopType;
  /** mass for this item in kg; null/NaN coerced to 0. */
  kg?: number | null;
}

function toKg(v: number | null | undefined): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

interface BreakdownEntry {
  rStrategy: CanonicalRStrategy;
  loopType: LoopType;
  events: number;
  kg: number;
  rate: number;
}

/**
 * Aggregate classified items into the deterministic (R-strategy, loop_type)
 * breakdown, kg-basis. `rate` is each composite's mass share (full precision —
 * the consumer rounds). Empty input → no entries, zero totals (rates 0, never
 * NaN). Entries sorted by compareComposite.
 */
function aggregatePathwayBreakdown(items: ClassifiedPathwayItem[]): BreakdownEntry[] {
  const acc = new Map<
    string,
    { rStrategy: CanonicalRStrategy; loopType: LoopType; events: number; kg: number }
  >();
  let totalKg = 0;

  for (const item of items) {
    const key = compositeKey(item.rStrategy, item.loopType);
    const bucket = acc.get(key) ??
      { rStrategy: item.rStrategy, loopType: item.loopType, events: 0, kg: 0 };
    bucket.events += 1;
    bucket.kg += toKg(item.kg);
    acc.set(key, bucket);
    totalKg += toKg(item.kg);
  }

  return [...acc.values()]
    .map((b) => ({
      rStrategy: b.rStrategy,
      loopType: b.loopType,
      events: b.events,
      kg: b.kg,
      rate: totalKg > 0 ? b.kg / totalKg : 0,
    }))
    .sort(compareComposite);
}

// =============================================================================
// Recompute the authoritative pathway_outputs[] block from raw input rows
// =============================================================================

/**
 * Reproduce the manifest's `pathway_outputs[]` block from the Tier 2
 * pathway-classification rows (`inputs[1]` — the {id, loop_type, quantity_kg,
 * r_strategy} projection on enhanced_transactions). Mirrors the producer's
 * `aggregatePathwayOutputs` exactly: normalise r_strategy (D10), drop rows that
 * do not classify, aggregate kg-basis, sort by compareComposite, round 4dp.
 *
 * CSV cells arrive as strings; `quantity_kg` is coerced to number and
 * empty/null becomes 0 (null_as_zero, matching the producer).
 */
export function recomputePathwayOutputs(
  rows: Array<Record<string, unknown>>,
): PathwayOutput[] {
  const items: ClassifiedPathwayItem[] = [];
  for (const row of rows) {
    const rawR =
      row.r_strategy == null ? null : String(row.r_strategy);
    const rStrategy = normaliseStoredRStrategy(rawR);
    const loopType = row.loop_type;
    if (!rStrategy || typeof loopType !== 'string' || loopType === '') continue;
    const kgCell = row.quantity_kg;
    items.push({
      rStrategy,
      loopType: loopType as LoopType,
      kg: kgCell == null || kgCell === '' ? null : Number(kgCell),
    });
  }

  return aggregatePathwayBreakdown(items).map((e) => ({
    r_strategy: e.rStrategy,
    loop_type: e.loopType,
    events: e.events,
    kg: roundHalfEven(e.kg),
    rate: roundHalfEven(e.rate),
  }));
}

// =============================================================================
// Comparison helpers (4dp tolerance, mirroring the producer's signed values)
// =============================================================================

/** 4dp tolerance — both sides are already roundHalfEven(_, 4), so this is a
 *  floating-point safety net, identical in spirit to recompute.metricsApproxEqual. */
const PATHWAY_TOLERANCE = 0.00005;

function approxEqual(a: number, b: number): boolean {
  return Math.abs(a - b) < PATHWAY_TOLERANCE;
}

export type PathwayCompareResult =
  | { ok: true }
  | { ok: false; detail: string };

/**
 * Compare the recomputed block against the signed `pathway_outputs[]` block,
 * element-wise in canonical order. Both are sorted by compareComposite, so a
 * positional walk is correct. `events` must match exactly; `kg` and `rate`
 * within 4dp tolerance. The first divergence is named.
 */
export function comparePathwayBlock(
  recomputed: PathwayOutput[],
  signed: PathwayOutput[],
): PathwayCompareResult {
  if (recomputed.length !== signed.length) {
    return {
      ok: false,
      detail:
        `Recomputed ${recomputed.length} pathway entries but the signed block has ${signed.length}. ` +
        `Composite (r_strategy, loop_type) set differs between the Tier 2 input and the signed binding.`,
    };
  }
  for (let i = 0; i < signed.length; i++) {
    const r = recomputed[i]!;
    const s = signed[i]!;
    if (r.r_strategy !== s.r_strategy || r.loop_type !== s.loop_type) {
      return {
        ok: false,
        detail:
          `Pathway entry ${i} key mismatch: recomputed (${r.r_strategy}, ${r.loop_type}) ` +
          `vs signed (${s.r_strategy}, ${s.loop_type}). Ordering or classification diverged.`,
      };
    }
    if (r.events !== s.events) {
      return {
        ok: false,
        detail:
          `Pathway (${s.r_strategy}, ${s.loop_type}) events recomputed ${r.events} ` +
          `but signed ${s.events}.`,
      };
    }
    if (!approxEqual(r.kg, s.kg)) {
      return {
        ok: false,
        detail:
          `Pathway (${s.r_strategy}, ${s.loop_type}) kg recomputed ${r.kg} ` +
          `but signed ${s.kg} (4dp tolerance).`,
      };
    }
    if (!approxEqual(r.rate, s.rate)) {
      return {
        ok: false,
        detail:
          `Pathway (${s.r_strategy}, ${s.loop_type}) rate recomputed ${r.rate} ` +
          `but signed ${s.rate} (4dp tolerance).`,
      };
    }
  }
  return { ok: true };
}

/**
 * The L2 `outcomes_by_r_strategy` projection, in its post-P5b composite form
 * (D1 = B): an array of typed entries, same key shape as the block minus `rate`
 * (rate is manifest-only per the P5a completion note — the equality assertion is
 * on (events, kg)).
 */
export interface L2ProjectionEntry {
  r_strategy: string;
  loop_type: string;
  events: number;
  kg: number;
}

export type ProjectionCompareResult =
  | { status: 'match' }
  | { status: 'mismatch'; detail: string }
  | { status: 'absent'; detail: string };

/**
 * Assert the L2 `outcomes_by_r_strategy` projection equals the signed block at
 * 4dp on (events, kg) — D2 = A (the block is authoritative; the L2 is a checked
 * projection).
 *
 * Discriminates the wire form: the post-P5b composite projection is an ARRAY of
 * {r_strategy, loop_type, events, kg}. The pre-P5b coarse projection is a
 * Record keyed by r_strategy only — that cannot be asserted against the
 * composite block, so it is reported `absent` (not a mismatch): until P5b lands,
 * the projection simply is not in composite form. The recompute-vs-block check
 * (the authoritative one) still runs regardless.
 */
export function compareL2Projection(
  projection: unknown,
  block: PathwayOutput[],
): ProjectionCompareResult {
  if (!Array.isArray(projection)) {
    return {
      status: 'absent',
      detail:
        'No composite outcomes_by_r_strategy projection on the published metrics ' +
        '(pre-P5b coarse form or absent). The authoritative signed block was still recomputed.',
    };
  }
  const proj = projection as L2ProjectionEntry[];
  if (proj.length !== block.length) {
    return {
      status: 'mismatch',
      detail:
        `L2 projection has ${proj.length} composite entries but the signed block has ${block.length}.`,
    };
  }
  const blockByKey = new Map(block.map((e) => [compositeKey(e.r_strategy, e.loop_type), e]));
  for (const p of proj) {
    const key = compositeKey(p.r_strategy, p.loop_type);
    const b = blockByKey.get(key);
    if (!b) {
      return {
        status: 'mismatch',
        detail: `L2 projection carries (${p.r_strategy}, ${p.loop_type}) which is absent from the signed block.`,
      };
    }
    if (Number(p.events) !== b.events) {
      return {
        status: 'mismatch',
        detail:
          `L2 projection (${p.r_strategy}, ${p.loop_type}) events ${p.events} ` +
          `≠ signed block ${b.events}.`,
      };
    }
    if (!approxEqual(Number(p.kg), b.kg)) {
      return {
        status: 'mismatch',
        detail:
          `L2 projection (${p.r_strategy}, ${p.loop_type}) kg ${p.kg} ` +
          `≠ signed block ${b.kg} (4dp tolerance).`,
      };
    }
  }
  return { status: 'match' };
}
