// src/recompute.ts
//
// Per-source metric recompute. Mirrors the source's per-source compute paths in
// CirculrDesignerGA/supabase/functions/publish-to-passport/index.ts:519-616
// (commit b3bfc026).
//
// Source uses `Math.round(x * 10000) / 10000` for the four published metric
// values (premium_pathway_rate, net_carbon_impact_kg, carbon_payback_ratio,
// transaction_count) — half-away-from-zero, NOT `roundHalfEven`. The verifier
// uses the same rounder so byte-equal reproductions match in all cases. The
// canonical-JSON hash binding happens elsewhere (crypto.ts canonicalJsonStringify
// re-rounds via roundHalfEven, which is a no-op on values that already sit at
// 4dp from Math.round).
//
// Tier 1 reproducibility per source (spec §3.1 / §5.5):
//
// | source                | reproducible from Tier 1? |
// | canonical_pipeline    | yes — sums co2e_kg by co2e_type |
// | enhanced_journeys     | partial — Tier 1 carries `co2e` per row but not `metrics.net_carbon_impact_kg`. Net carbon falls back to `co2e`; premium rate from `outcome_type` is exact. |
// | precomputed_sorting   | yes — sums avoided_emissions + total_program_emissions_kg |
// | designtime_estimation | yes — averages yield_pct |
//
// `transaction_count` is queried against `enhanced_transactions` at publish
// time. It is not derivable from any Tier 1 or Tier 2 export. The verifier
// trusts the published value and binds it through the metrics-hash check.

import type { MetricsSource } from './crypto.js';

/**
 * The subset of programme_metrics that the verifier can recompute from Tier 1
 * inputs. Each value matches the source's `Math.round(x * 10000) / 10000`
 * rounding so the verifier can compare at byte-equality.
 */
export interface RecomputedMetrics {
  premium_pathway_rate: number;
  net_carbon_impact_kg: number;
  carbon_payback_ratio: number;
  /**
   * Which fields the verifier could actually recompute from Tier 1 rows for
   * this source. Fields outside this set are not derivable from Tier 1 and
   * MUST NOT be asserted against published values during the metric-
   * recomputation check.
   */
  recomputed_fields: Array<'premium_pathway_rate' | 'net_carbon_impact_kg' | 'carbon_payback_ratio'>;
}

/** Round half-away-from-zero at 4dp — mirrors source line 622-624. */
function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

/** Coerce CSV cells to number (Tier 1 / Tier 2 CSVs serialise numbers as decimal strings). */
function num(v: unknown): number {
  if (v === null || v === undefined || v === '') return 0;
  if (typeof v === 'number') return Number.isFinite(v) ? v : 0;
  const parsed = Number(v);
  return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * canonical_pipeline — material_flow_co2e rows.
 *
 * Tier 1 columns: ['co2e_kg', 'co2e_type', 'id']
 * Source paths: index.ts:519-540.
 *
 *   totalAvoided   = sum(co2e_kg where co2e_type is a benefit)
 *   totalGenerated = sum(co2e_kg where co2e_type is a burden)
 *   net_carbon_impact_kg = totalAvoided - totalGenerated
 *   carbon_payback_ratio = totalGenerated > 0 ? totalAvoided / totalGenerated : 0
 *   premium_pathway_rate = 0 (canonical_pipeline doesn't set premium rate)
 *
 * Benefit set is VERSION-GATED (mirrors the producer's transform identity):
 *   - function_version < 4 (≤ 4.0.0): benefit = {avoided}; displacement is a burden.
 *   - function_version >= 4.1.0 (creditDisplacement=true): benefit = {avoided, displacement}.
 *     SPEC_LCA_Composition_Fallback_v190 §Fork-3 — reuse displacement IS avoided CO₂e. The CDGA
 *     producer credited it from 4.1.0 (publish-to-passport canonicalPipelineMetrics.ts). Archived
 *     pre-4.1.0 manifests were SIGNED with displacement as a burden, so they MUST reproduce that way
 *     — hence the gate (caller passes creditDisplacement = manifestMajorVersion >= 4). Default false
 *     is archival-safe (unknown/old version → burden).
 */
export function recomputeCanonicalPipeline(
  rows: Array<Record<string, unknown>>,
  creditDisplacement = false,
): RecomputedMetrics {
  let totalAvoided = 0;
  let totalGenerated = 0;
  for (const row of rows) {
    const co2e = num(row.co2e_kg);
    const isBenefit = row.co2e_type === 'avoided' || (creditDisplacement && row.co2e_type === 'displacement');
    if (isBenefit) totalAvoided += co2e;
    else totalGenerated += co2e;
  }
  const netCarbonImpact = totalAvoided - totalGenerated;
  const carbonPaybackRatio = totalGenerated > 0 ? totalAvoided / totalGenerated : 0;
  return {
    premium_pathway_rate: round4(0),
    net_carbon_impact_kg: round4(netCarbonImpact),
    carbon_payback_ratio: round4(carbonPaybackRatio),
    recomputed_fields: ['net_carbon_impact_kg', 'carbon_payback_ratio'],
  };
}

/**
 * enhanced_journeys — journey-level aggregation.
 *
 * Tier 1 columns: ['co2e', 'id', 'outcome_type']
 * Source paths: index.ts:542-565.
 *
 *   totalJourneys     = rows.length
 *   circularJourneys  = rows where outcome_type === 'circular'
 *   premium_pathway_rate = totalJourneys > 0 ? circularJourneys / totalJourneys : 0
 *   net_carbon_impact_kg = sum(metrics.net_carbon_impact_kg ?? co2e ?? 0)
 *
 * Tier 1 carries `co2e` per row but not `metrics`. The recompute falls back to
 * `co2e` for every row, which matches the source's fallback. If the source
 * actually used `metrics.net_carbon_impact_kg` for any row (Tier 2 only), the
 * Tier 1 recompute will mismatch — that's the intended ceiling on Tier 1
 * verification per spec §11.2.
 */
export function recomputeEnhancedJourneys(rows: Array<Record<string, unknown>>): RecomputedMetrics {
  const totalJourneys = rows.length;
  const circularJourneys = rows.filter((j) => j.outcome_type === 'circular').length;
  const premiumRate = totalJourneys > 0 ? circularJourneys / totalJourneys : 0;

  let netCarbonImpact = 0;
  for (const j of rows) {
    // Tier 2 carries `metrics` JSON; Tier 1 does not.
    const metrics = j.metrics as { net_carbon_impact_kg?: number } | undefined;
    netCarbonImpact += metrics?.net_carbon_impact_kg ?? num(j.co2e);
  }

  return {
    premium_pathway_rate: round4(premiumRate),
    net_carbon_impact_kg: round4(netCarbonImpact),
    carbon_payback_ratio: round4(0),
    recomputed_fields: ['premium_pathway_rate', 'net_carbon_impact_kg'],
  };
}

/**
 * precomputed_sorting — RMW pilot bypass.
 *
 * Tier 1 columns: ['avoided_emissions', 'id', 'total_program_emissions_kg']
 * Source paths: index.ts:567-600.
 *
 * `avoided_emissions` is JSONB on the source table. After CSV serialisation
 * it appears either as a JSON-stringified object (`{"kg": 42}`) or as a
 * decimal number cell. The recompute mirrors the source's defensive coercion:
 * if a number, use it directly; if a JSON object with a `kg` numeric field,
 * use that; else 0.
 *
 *   premium_pathway_rate = 0 (per source comment — pathway-based premium was
 *                              always returning 0 because the column reference
 *                              was broken; preserved for byte-equality)
 *   net_carbon_impact_kg = totalAvoided - totalGenerated
 *   carbon_payback_ratio = totalGenerated > 0 ? totalAvoided / totalGenerated : 0
 */
export function recomputePrecomputedSorting(rows: Array<Record<string, unknown>>): RecomputedMetrics {
  let totalAvoided = 0;
  let totalGenerated = 0;
  for (const item of rows) {
    const ae = item.avoided_emissions;
    if (typeof ae === 'number') {
      totalAvoided += ae;
    } else if (typeof ae === 'string' && ae !== '') {
      // CSV cell may be a JSON-stringified object or a stringified number.
      const asNumber = Number(ae);
      if (Number.isFinite(asNumber)) {
        totalAvoided += asNumber;
      } else {
        try {
          const parsed = JSON.parse(ae) as { kg?: unknown };
          if (typeof parsed.kg === 'number') totalAvoided += parsed.kg;
        } catch {
          // Unparseable cell — treat as 0 (matches source's null-handling).
        }
      }
    } else if (ae && typeof ae === 'object' && 'kg' in ae) {
      const kg = (ae as { kg: unknown }).kg;
      if (typeof kg === 'number') totalAvoided += kg;
    }
    totalGenerated += num(item.total_program_emissions_kg);
  }
  const netCarbonImpact = totalAvoided - totalGenerated;
  const carbonPaybackRatio = totalGenerated > 0 ? totalAvoided / totalGenerated : 0;
  return {
    premium_pathway_rate: round4(0),
    net_carbon_impact_kg: round4(netCarbonImpact),
    carbon_payback_ratio: round4(carbonPaybackRatio),
    recomputed_fields: ['premium_pathway_rate', 'net_carbon_impact_kg', 'carbon_payback_ratio'],
  };
}

/**
 * designtime_estimation — pre-operational estimate.
 *
 * Tier 1 columns: ['id', 'node_id', 'yield_pct']
 * Source paths: index.ts:602-616.
 *
 *   avgYield = sum(yield_pct) / rows.length
 *   premium_pathway_rate = avgYield
 *   net_carbon_impact_kg = 0 (designtime path doesn't write this)
 *   carbon_payback_ratio = 0
 */
export function recomputeDesigntimeEstimation(rows: Array<Record<string, unknown>>): RecomputedMetrics {
  if (rows.length === 0) {
    return {
      premium_pathway_rate: 0,
      net_carbon_impact_kg: 0,
      carbon_payback_ratio: 0,
      recomputed_fields: [],
    };
  }
  const avgYield = rows.reduce((sum, c) => sum + num(c.yield_pct), 0) / rows.length;
  return {
    premium_pathway_rate: round4(avgYield),
    net_carbon_impact_kg: round4(0),
    carbon_payback_ratio: round4(0),
    recomputed_fields: ['premium_pathway_rate'],
  };
}

/**
 * Dispatch by metrics_source. Caller has the parsed CSV rows already.
 */
export function recomputeForSource(
  source: MetricsSource,
  rows: Array<Record<string, unknown>>,
  creditDisplacement = false,
): RecomputedMetrics {
  switch (source) {
    case 'canonical_pipeline':
      return recomputeCanonicalPipeline(rows, creditDisplacement);
    case 'enhanced_journeys':
      return recomputeEnhancedJourneys(rows);
    case 'precomputed_sorting':
      return recomputePrecomputedSorting(rows);
    case 'designtime_estimation':
      return recomputeDesigntimeEstimation(rows);
  }
}

/**
 * Compare two metric values at 4dp tolerance. Both sides have already been
 * rounded to 4dp via round4(), so equality is exact; the tolerance is a
 * safety net for floating-point representation edge cases.
 */
export function metricsApproxEqual(a: number, b: number): boolean {
  return Math.abs(a - b) < 0.00005;
}
