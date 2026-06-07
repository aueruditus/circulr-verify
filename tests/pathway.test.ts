// tests/pathway.test.ts
//
// Unit tests for the D4 composite-pathway reference implementation (src/pathway.ts).
// These pin the determinism contract the producer signs against — D10 r_strategy
// normalisation, the §5.4 numeric-R sort, the R11 closed/open split, and the two
// comparators (block + L2 projection). Drift here = false MISMATCH on real prod
// manifests, so the assertions are deliberately tight.

import { describe, it, expect } from 'vitest';
import {
  normaliseStoredRStrategy,
  compareComposite,
  recomputePathwayOutputs,
  comparePathwayBlock,
  compareL2Projection,
  type PathwayOutput,
} from '../src/pathway.js';

describe('normaliseStoredRStrategy (D10)', () => {
  it('honours an already-canonical bare code (case-insensitive)', () => {
    expect(normaliseStoredRStrategy('R1')).toBe('R1');
    expect(normaliseStoredRStrategy('r11')).toBe('R11');
    expect(normaliseStoredRStrategy('R12')).toBe('R12');
  });

  it('reconciles on the strategy NAME, discarding the unreliable numeric prefix', () => {
    // The name wins: "R3_Reuse" → reuse → R5 (NOT R3); "r7_recycle" → recycle → R11.
    expect(normaliseStoredRStrategy('R3_Reuse')).toBe('R5');
    expect(normaliseStoredRStrategy('r2_reuse')).toBe('R5');
    expect(normaliseStoredRStrategy('r7_recycle')).toBe('R11');
    expect(normaliseStoredRStrategy('recycle')).toBe('R11');
  });

  it('normalises separators and casing in the name', () => {
    expect(normaliseStoredRStrategy('re-earth')).toBe('R10');
    expect(normaliseStoredRStrategy('Re Earth')).toBe('R10');
    expect(normaliseStoredRStrategy('REMANUFACTURE')).toBe('R8');
  });

  it('returns null for null / undefined / blank input', () => {
    expect(normaliseStoredRStrategy(null)).toBeNull();
    expect(normaliseStoredRStrategy(undefined)).toBeNull();
    expect(normaliseStoredRStrategy('')).toBeNull();
    expect(normaliseStoredRStrategy('   ')).toBeNull();
  });

  it('returns null for an unrecognised name and an out-of-range bare code', () => {
    expect(normaliseStoredRStrategy('frobnicate')).toBeNull();
    // R13 is out of range → not a bare code → legacy path strips "r13" → '' → null.
    expect(normaliseStoredRStrategy('R13')).toBeNull();
  });
});

describe('compareComposite (§5.4 SSOT sort)', () => {
  it('orders R-strategy by NUMERIC value, not lexicographically (R2 before R10)', () => {
    expect(
      compareComposite({ rStrategy: 'R2', loopType: 'reuse' }, { rStrategy: 'R10', loopType: 'reuse' }),
    ).toBeLessThan(0);
    // Lexicographic would put "R11" before "R5" — the numeric sort must not.
    expect(
      compareComposite({ rStrategy: 'R5', loopType: 'reuse' }, { rStrategy: 'R11', loopType: 'reuse' }),
    ).toBeLessThan(0);
  });

  it('tie-breaks equal R-strategy by loop_type lexicographic ascending', () => {
    expect(
      compareComposite(
        { rStrategy: 'R11', loopType: 'closed_loop' },
        { rStrategy: 'R11', loopType: 'open_loop_downcycle' },
      ),
    ).toBeLessThan(0);
    expect(
      compareComposite(
        { rStrategy: 'R11', loopType: 'closed_loop' },
        { rStrategy: 'R11', loopType: 'closed_loop' },
      ),
    ).toBe(0);
  });
});

describe('recomputePathwayOutputs', () => {
  it('aggregates kg-basis, splits R11 into closed_loop + open_loop_downcycle, sorts numeric-R', () => {
    const rows = [
      { id: 't1', loop_type: 'reuse', quantity_kg: '8', r_strategy: 'R5' },
      { id: 't2', loop_type: 'closed_loop', quantity_kg: '20', r_strategy: 'R11' },
      { id: 't3', loop_type: 'open_loop_downcycle', quantity_kg: '12', r_strategy: 'R11' },
    ];
    const out = recomputePathwayOutputs(rows);
    // R5 (numeric 5) sorts before R11 — and R11 splits into two loop_type entries.
    expect(out).toEqual<PathwayOutput[]>([
      { r_strategy: 'R5', loop_type: 'reuse', events: 1, kg: 8, rate: 0.2 },
      { r_strategy: 'R11', loop_type: 'closed_loop', events: 1, kg: 20, rate: 0.5 },
      { r_strategy: 'R11', loop_type: 'open_loop_downcycle', events: 1, kg: 12, rate: 0.3 },
    ]);
  });

  it('sums events and kg within a composite, applying D10 to drifted stored forms', () => {
    const rows = [
      { id: 't1', loop_type: 'reuse', quantity_kg: '10.5', r_strategy: 'R3_Reuse' }, // → R5
      { id: 't2', loop_type: 'reuse', quantity_kg: '8.1', r_strategy: 'r2_reuse' }, // → R5
    ];
    const out = recomputePathwayOutputs(rows);
    expect(out).toEqual<PathwayOutput[]>([
      { r_strategy: 'R5', loop_type: 'reuse', events: 2, kg: 18.6, rate: 1 },
    ]);
  });

  it('drops rows that do not classify (null r_strategy or blank loop_type)', () => {
    const rows = [
      { id: 't1', loop_type: 'reuse', quantity_kg: '5', r_strategy: 'R5' },
      { id: 't2', loop_type: 'reuse', quantity_kg: '5', r_strategy: 'frobnicate' }, // unrecognised → dropped
      { id: 't3', loop_type: '', quantity_kg: '5', r_strategy: 'R5' }, // blank loop_type → dropped
      { id: 't4', loop_type: 'reuse', quantity_kg: '5', r_strategy: null }, // null r_strategy → dropped
    ];
    const out = recomputePathwayOutputs(rows);
    expect(out).toEqual<PathwayOutput[]>([
      { r_strategy: 'R5', loop_type: 'reuse', events: 1, kg: 5, rate: 1 },
    ]);
  });

  it('coerces null/blank quantity_kg to 0 (null_as_zero), never NaN', () => {
    const rows = [
      { id: 't1', loop_type: 'reuse', quantity_kg: '', r_strategy: 'R5' },
      { id: 't2', loop_type: 'reuse', quantity_kg: null, r_strategy: 'R5' },
    ];
    const out = recomputePathwayOutputs(rows);
    expect(out).toEqual<PathwayOutput[]>([
      { r_strategy: 'R5', loop_type: 'reuse', events: 2, kg: 0, rate: 0 },
    ]);
  });

  it('returns an empty block for empty input', () => {
    expect(recomputePathwayOutputs([])).toEqual([]);
  });
});

describe('comparePathwayBlock', () => {
  const signed: PathwayOutput[] = [
    { r_strategy: 'R5', loop_type: 'reuse', events: 1, kg: 8, rate: 0.2 },
    { r_strategy: 'R11', loop_type: 'closed_loop', events: 1, kg: 20, rate: 0.5 },
  ];

  it('matches an identical block', () => {
    expect(comparePathwayBlock([...signed], signed).ok).toBe(true);
  });

  it('tolerates kg/rate within 4dp', () => {
    const recomputed: PathwayOutput[] = [
      { r_strategy: 'R5', loop_type: 'reuse', events: 1, kg: 8.00001, rate: 0.20001 },
      { r_strategy: 'R11', loop_type: 'closed_loop', events: 1, kg: 20, rate: 0.5 },
    ];
    expect(comparePathwayBlock(recomputed, signed).ok).toBe(true);
  });

  it('flags a length divergence', () => {
    const r = comparePathwayBlock([signed[0]!], signed);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toMatch(/entries|set differs/i);
  });

  it('flags a key (classification/ordering) divergence', () => {
    const recomputed: PathwayOutput[] = [
      { r_strategy: 'R6', loop_type: 'reuse', events: 1, kg: 8, rate: 0.2 },
      signed[1]!,
    ];
    const r = comparePathwayBlock(recomputed, signed);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toMatch(/key mismatch/i);
  });

  it('flags an events divergence (exact match required)', () => {
    const recomputed = [{ ...signed[0]!, events: 2 }, signed[1]!];
    const r = comparePathwayBlock(recomputed, signed);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toMatch(/events/i);
  });

  it('flags a kg divergence beyond tolerance', () => {
    const recomputed = [{ ...signed[0]!, kg: 8.5 }, signed[1]!];
    const r = comparePathwayBlock(recomputed, signed);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toMatch(/kg/i);
  });
});

describe('compareL2Projection', () => {
  const block: PathwayOutput[] = [
    { r_strategy: 'R5', loop_type: 'reuse', events: 2, kg: 18.6, rate: 0.2616 },
    { r_strategy: 'R11', loop_type: 'closed_loop', events: 3, kg: 40.5, rate: 0.5696 },
  ];

  it('matches a composite array projection equal at (events, kg)', () => {
    const proj = block.map((e) => ({ r_strategy: e.r_strategy, loop_type: e.loop_type, events: e.events, kg: e.kg }));
    expect(compareL2Projection(proj, block).status).toBe('match');
  });

  it('reports absent for a non-array (pre-P5b coarse / missing) projection', () => {
    expect(compareL2Projection(undefined, block).status).toBe('absent');
    expect(compareL2Projection({ R5: 18.6 }, block).status).toBe('absent');
  });

  it('reports mismatch on a length divergence', () => {
    const proj = [{ r_strategy: 'R5', loop_type: 'reuse', events: 2, kg: 18.6 }];
    expect(compareL2Projection(proj, block).status).toBe('mismatch');
  });

  it('reports mismatch when a projection key is absent from the block', () => {
    const proj = [
      { r_strategy: 'R5', loop_type: 'reuse', events: 2, kg: 18.6 },
      { r_strategy: 'R6', loop_type: 'closed_loop', events: 3, kg: 40.5 },
    ];
    const r = compareL2Projection(proj, block);
    expect(r.status).toBe('mismatch');
    if (r.status === 'mismatch') expect(r.detail).toMatch(/absent from the signed block/i);
  });

  it('reports mismatch on an events / kg divergence', () => {
    const projEvents = [
      { r_strategy: 'R5', loop_type: 'reuse', events: 9, kg: 18.6 },
      { r_strategy: 'R11', loop_type: 'closed_loop', events: 3, kg: 40.5 },
    ];
    expect(compareL2Projection(projEvents, block).status).toBe('mismatch');
    const projKg = [
      { r_strategy: 'R5', loop_type: 'reuse', events: 2, kg: 99 },
      { r_strategy: 'R11', loop_type: 'closed_loop', events: 3, kg: 40.5 },
    ];
    expect(compareL2Projection(projKg, block).status).toBe('mismatch');
  });
});
