// tests/fixtures/_generate.ts
//
// Reproducible fixture generator. Round-trips through src/crypto.ts so fixtures
// and verifier cannot drift independently.
//
//   npm run fixtures:regenerate
//
// Produces:
//   keys.json                              ES256 P-256 keypair (jwk format) for fixture signing
//   manifest_canonical_pipeline.json
//   manifest_enhanced_journeys.json
//   manifest_precomputed_sorting.json
//   manifest_designtime_estimation.json
//   manifest_input_integrity.json          Phase 7c claim_level fixture
//   tier1_canonical_pipeline.csv
//   tier1_enhanced_journeys.csv
//   tier1_precomputed_sorting.csv
//   tier1_designtime_estimation.csv
//   tier2_canonical_pipeline.csv           For Input Integrity test
//   metrics_*.json                         The published `metrics` row for each manifest

import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  base64UrlEncode,
  canonicalJsonStringify,
  sha256Hex,
  type ComputationManifest,
} from '../../src/crypto.js';
import { recomputePathwayOutputs } from '../../src/pathway.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// =============================================================================
// Round-half-even rounder, lifted from crypto.ts (deliberate — fixture
// generator uses crypto.ts's exported helpers).
// =============================================================================

// (Re-imported via the canonical helpers below.)

// =============================================================================
// Helpers — mirror the source's canonical-CSV serialiser in shape.
// =============================================================================

const ROW_SEPARATOR = '\r\n';

function csvEscape(cell: string): string {
  if (/[",\r\n]/.test(cell)) return '"' + cell.replace(/"/g, '""') + '"';
  return cell;
}

function canonicaliseValueForCsv(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return '';
    // Use the same round-half-even contract as the source's CSV serialiser.
    return roundHalfEvenLocal(v).toString();
  }
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'string') return v;
  if (v instanceof Date) return v.toISOString();
  return canonicalJsonStringify(v);
}

function rowsToCanonicalCsv(rows: Array<Record<string, unknown>>, columns: string[]): string {
  const sortedCols = [...columns];
  const header = sortedCols.map(csvEscape).join(',');
  const dataRows = rows.map((row) => sortedCols.map((c) => csvEscape(canonicaliseValueForCsv(row[c]))).join(','));
  return [header, ...dataRows].join(ROW_SEPARATOR);
}

function roundHalfEvenLocal(v: number, decimals = 4): number {
  if (!Number.isFinite(v)) return v;
  const factor = Math.pow(10, decimals);
  const scaled = v * factor;
  const floor = Math.floor(scaled);
  const diff = scaled - floor;
  const EPSILON = 1e-9;
  if (Math.abs(diff - 0.5) < EPSILON) return (floor % 2 === 0 ? floor : floor + 1) / factor;
  return Math.round(scaled) / factor;
}

// =============================================================================
// Keypair + signing helpers
// =============================================================================

async function generateKeypair(): Promise<{ privateJwk: JsonWebKey; publicJwk: JsonWebKey; kid: string }> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const kid = 'circulr-fixture-2026-05';
  privateJwk.kid = kid;
  publicJwk.kid = kid;
  publicJwk.alg = 'ES256';
  publicJwk.use = 'sig';
  return { privateJwk, publicJwk, kid };
}

async function signManifest(
  bodyCanonical: string,
  privateJwk: JsonWebKey,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(bodyCanonical),
  );
  return base64UrlEncode(new Uint8Array(sig));
}

// =============================================================================
// Per-source fixture builders
// =============================================================================

const KEY_URL = 'https://fixtures.local/.well-known/verification-keys.json';
const PROGRAMME_ID = 'prog-fixture-1';
const CANVAS_ID = 'canvas-fixture-1';
const PUBLISHED_VERSION = 3;
const COMPUTED_AT = '2026-05-04T08:42:11.000Z';
const TRANSFORM = {
  function_id: 'circulr.publish-to-passport.programme-metrics',
  function_version: '1.0.0',
  function_url: 'https://circulrdesigner.circulr.ai/transforms/circulr.publish-to-passport.programme-metrics/1.0.0/manifest.json',
  description: 'Programme metrics computation pipeline for au.com.auspost.sustainability §7-conformant manifests.',
};

const TRANSFORM_V2 = {
  function_id: 'circulr.publish-to-passport.programme-metrics',
  function_version: '2.0.0',
  function_url: 'https://circulrdesigner.circulr.ai/transforms/circulr.publish-to-passport.programme-metrics/2.0.0/manifest.json',
  description:
    'Programme metrics computation pipeline for au.com.auspost.sustainability §7-conformant manifests. ' +
    'v2.0.0 hashes a second input — the per-transaction pathway classification (the (r_strategy, loop_type) ' +
    'key on enhanced_transactions) — and binds an authoritative output.pathway_outputs[] breakdown aggregated ' +
    'from those same rows.',
};

const TRANSFORM_V3 = {
  function_id: 'circulr.publish-to-passport.programme-metrics',
  function_version: '3.0.0',
  function_url: 'https://circulrdesigner.circulr.ai/transforms/circulr.publish-to-passport.programme-metrics/3.0.0/manifest.json',
  description:
    'Programme metrics computation pipeline for au.com.auspost.sustainability §7-conformant manifests. ' +
    'v3.0.0 binds output.metrics_hash to a defined canonical metrics projection embedded as output.metrics, ' +
    'making the scalar claim self-contained and reproducible without the passport endpoint serialisation.',
};

interface Fixture {
  manifest: ComputationManifest;
  tier1Csv: string;
  tier2Csv?: string;
  /** v2.0.0 only — the inputs[1] pathway-classification CSV. */
  pathwayCsv?: string;
  metrics: Record<string, unknown>;
}

async function buildCanonicalPipelineFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  // Tier 1 columns: co2e_kg, co2e_type, id
  // Tier 2 columns: co2e_kg, co2e_type, emission_factor_id, emission_factor_value, id, material_flow_record_id, quantity_kg
  const tier2Rows = [
    { co2e_kg: 5, co2e_type: 'avoided', emission_factor_id: 'ef1', emission_factor_value: 0.5, id: 'r1', material_flow_record_id: 'm1', quantity_kg: 10 },
    { co2e_kg: 3, co2e_type: 'avoided', emission_factor_id: 'ef1', emission_factor_value: 0.5, id: 'r2', material_flow_record_id: 'm2', quantity_kg: 6 },
    { co2e_kg: 2, co2e_type: 'generated', emission_factor_id: 'ef2', emission_factor_value: 1, id: 'r3', material_flow_record_id: 'm3', quantity_kg: 2 },
  ];
  const tier2Columns = ['co2e_kg', 'co2e_type', 'emission_factor_id', 'emission_factor_value', 'id', 'material_flow_record_id', 'quantity_kg'];
  const tier2Csv = rowsToCanonicalCsv(tier2Rows, tier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);

  const tier1Rows = tier2Rows.map((r) => ({ co2e_kg: r.co2e_kg, co2e_type: r.co2e_type, id: r.id }));
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, ['co2e_kg', 'co2e_type', 'id']);

  // Source-side metric values: totalAvoided=8, totalGenerated=2, netCarbon=6, ratio=4
  const metrics = {
    programme_id: PROGRAMME_ID,
    premium_pathway_rate: 0,
    net_carbon_impact_kg: 6,
    carbon_payback_ratio: 4,
    transaction_count: 0,
    data_status: 'measured',
    metrics_source: 'canonical_pipeline',
    period: null,
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(metrics));

  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [{
      dataset: 'material_flow_co2e',
      row_count: tier2Rows.length,
      hash: tier2Hash,
      columns: tier2Columns,
      period_start: null,
      period_end: null,
    }],
    output: { metrics_hash: metricsHash, metrics_source: 'canonical_pipeline' },
    computation: {
      transform: TRANSFORM,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  return { manifest, tier1Csv, tier2Csv, metrics };
}

async function buildEnhancedJourneysFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  // Tier 1 columns: co2e, id, outcome_type
  const tier1Rows = [
    { co2e: 1.5, id: 'j1', outcome_type: 'circular' },
    { co2e: 2.5, id: 'j2', outcome_type: 'circular' },
    { co2e: 4, id: 'j3', outcome_type: 'linear' },
    { co2e: 2, id: 'j4', outcome_type: 'circular' },
  ];
  const tier1Columns = ['co2e', 'id', 'outcome_type'];
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, tier1Columns);
  // Tier 2 has the same plus canvas_id, created_at, metrics — for this fixture
  // we pretend `metrics` is null on every row so `co2e` is the fallback.
  const tier2Rows = tier1Rows.map((r) => ({
    canvas_id: CANVAS_ID,
    co2e: r.co2e,
    created_at: '2026-05-01T00:00:00.000Z',
    id: r.id,
    metrics: null,
    outcome_type: r.outcome_type,
  }));
  const tier2Columns = ['canvas_id', 'co2e', 'created_at', 'id', 'metrics', 'outcome_type'];
  const tier2Csv = rowsToCanonicalCsv(tier2Rows, tier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);

  // Source-side: totalJourneys=4, circular=3, premiumRate=0.75, sum co2e=10
  const metrics = {
    programme_id: PROGRAMME_ID,
    premium_pathway_rate: 0.75,
    net_carbon_impact_kg: 10,
    carbon_payback_ratio: 0,
    transaction_count: 0,
    data_status: 'measured',
    metrics_source: 'enhanced_journeys',
    period: '2026-05-01 to 2026-05-01',
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(metrics));
  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [{
      dataset: 'enhanced_journeys',
      row_count: tier2Rows.length,
      hash: tier2Hash,
      columns: tier2Columns,
      period_start: '2026-05-01T00:00:00.000Z',
      period_end: '2026-05-01T00:00:00.000Z',
    }],
    output: { metrics_hash: metricsHash, metrics_source: 'enhanced_journeys' },
    computation: {
      transform: TRANSFORM,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  return { manifest, tier1Csv, tier2Csv, metrics };
}

async function buildPrecomputedSortingFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  // Tier 1 columns: avoided_emissions, id, total_program_emissions_kg
  // avoided_emissions is JSONB — typically {"kg": N} in source. After
  // canonicalisation the CSV cell becomes JSON-stringified.
  const tier2Rows = [
    { avoided_emissions: 10, canvas_id: CANVAS_ID, id: 's1', total_program_emissions_kg: 4 },
    { avoided_emissions: 8, canvas_id: CANVAS_ID, id: 's2', total_program_emissions_kg: 2 },
  ];
  const tier2Columns = ['avoided_emissions', 'canvas_id', 'id', 'total_program_emissions_kg'];
  const tier2Csv = rowsToCanonicalCsv(tier2Rows, tier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);

  const tier1Rows = tier2Rows.map((r) => ({
    avoided_emissions: r.avoided_emissions,
    id: r.id,
    total_program_emissions_kg: r.total_program_emissions_kg,
  }));
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, ['avoided_emissions', 'id', 'total_program_emissions_kg']);

  // totalAvoided=18, totalGenerated=6, net=12, ratio=3
  const metrics = {
    programme_id: PROGRAMME_ID,
    premium_pathway_rate: 0,
    net_carbon_impact_kg: 12,
    carbon_payback_ratio: 3,
    transaction_count: 0,
    data_status: 'measured',
    metrics_source: 'precomputed_sorting',
    period: null,
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(metrics));
  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [{
      dataset: 'sorting_items',
      row_count: tier2Rows.length,
      hash: tier2Hash,
      columns: tier2Columns,
      period_start: null,
      period_end: null,
    }],
    output: { metrics_hash: metricsHash, metrics_source: 'precomputed_sorting' },
    computation: {
      transform: TRANSFORM,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  return { manifest, tier1Csv, tier2Csv, metrics };
}

async function buildDesigntimeEstimationFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  // Tier 1 columns: id, node_id, yield_pct
  const tier2Rows = [
    { canvas_id: CANVAS_ID, id: 'c1', node_id: 'n1', yield_pct: 0.8 },
    { canvas_id: CANVAS_ID, id: 'c2', node_id: 'n2', yield_pct: 0.6 },
    { canvas_id: CANVAS_ID, id: 'c3', node_id: 'n3', yield_pct: 0.7 },
  ];
  const tier2Columns = ['canvas_id', 'id', 'node_id', 'yield_pct'];
  const tier2Csv = rowsToCanonicalCsv(tier2Rows, tier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);

  const tier1Rows = tier2Rows.map((r) => ({ id: r.id, node_id: r.node_id, yield_pct: r.yield_pct }));
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, ['id', 'node_id', 'yield_pct']);

  const metrics = {
    programme_id: PROGRAMME_ID,
    premium_pathway_rate: 0.7,
    net_carbon_impact_kg: 0,
    carbon_payback_ratio: 0,
    transaction_count: 0,
    data_status: 'simulated',
    metrics_source: 'designtime_estimation',
    period: null,
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(metrics));
  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [{
      dataset: 'node_loop_throughput_config',
      row_count: tier2Rows.length,
      hash: tier2Hash,
      columns: tier2Columns,
      period_start: null,
      period_end: null,
    }],
    output: { metrics_hash: metricsHash, metrics_source: 'designtime_estimation' },
    computation: {
      transform: TRANSFORM,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  return { manifest, tier1Csv, tier2Csv, metrics };
}

/**
 * Phase 7c variant: same canonical_pipeline data but with `claim_level:
 * input_integrity` and an `independence_check` body block. Tests that the
 * verifier reads the field and reports honestly.
 */
async function buildInputIntegrityFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  const base = await buildCanonicalPipelineFixture(privateJwk, kid);
  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: base.manifest.programme_id,
    canvas_id: base.manifest.canvas_id,
    published_version: base.manifest.published_version,
    computed_at: base.manifest.computed_at,
    inputs: [{
      ...base.manifest.inputs[0]!,
      attestation_reference: {
        registry_url: null,
        aggregate_record_id: 'agg-fixture-1',
        manifest_hash_pinned: null,
      },
    }],
    output: base.manifest.output,
    computation: base.manifest.computation,
    claim_level: 'input_integrity',
    independence_check: {
      measurement_platform_id: 'org-circulr',
      attestor_id: 'org-circulr',
      certifier_ids: [],
      non_independent_pairs: [
        { left: 'measurement_platform', right: 'attestor', shared_id: 'org-circulr' },
      ],
      determined_level: 'input_integrity',
      determined_at: COMPUTED_AT,
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  return {
    manifest: { ...body, signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig } },
    tier1Csv: base.tier1Csv,
    tier2Csv: base.tier2Csv,
    metrics: base.metrics,
  };
}

/**
 * v2.0.0 fixture (BRIEFING_circulr_verify_Pathway_Verification item 5).
 *
 * Two inputs: inputs[0] = sorting_items (the precomputed_sorting scalar source),
 * inputs[1] = enhanced_transactions pathway classification ({id, loop_type,
 * quantity_kg, r_strategy}). The signed output carries the authoritative
 * pathway_outputs[] block — generated through src/pathway.recomputePathwayOutputs
 * so the fixture and the verifier cannot drift. The r_strategy column carries
 * DRIFTED stored forms (R3_Reuse, r7_recycle, …) to exercise D10 normalisation
 * end-to-end; the block carries canonical R-codes. The published metrics carry
 * the composite outcomes_by_r_strategy projection (D1 = B array) so the D2 = A
 * equality assertion has something to cross-check.
 */
async function buildV2PathwayFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  // inputs[1] — enhanced_transactions pathway classification (raw stored forms).
  const pathwayColumns = ['id', 'loop_type', 'quantity_kg', 'r_strategy'];
  const pathwayRows = [
    { id: 't1', loop_type: 'reuse', quantity_kg: 10.5, r_strategy: 'R3_Reuse' },
    { id: 't2', loop_type: 'reuse', quantity_kg: 8.1, r_strategy: 'r2_reuse' },
    { id: 't3', loop_type: 'closed_loop', quantity_kg: 20, r_strategy: 'R11' },
    { id: 't4', loop_type: 'closed_loop', quantity_kg: 15.5, r_strategy: 'r7_recycle' },
    { id: 't5', loop_type: 'closed_loop', quantity_kg: 5, r_strategy: 'recycle' },
    { id: 't6', loop_type: 'open_loop_downcycle', quantity_kg: 12, r_strategy: 'R11' },
  ];
  const pathwayCsv = rowsToCanonicalCsv(pathwayRows, pathwayColumns);
  const pathwayHash = await sha256Hex(pathwayCsv);
  // Through the real recompute path — the block the producer would sign.
  const pathwayOutputs = recomputePathwayOutputs(pathwayRows);
  // L2 composite projection (D1 = B): same key shape minus rate (events, kg).
  const outcomesByRStrategy = pathwayOutputs.map((e) => ({
    r_strategy: e.r_strategy,
    loop_type: e.loop_type,
    events: e.events,
    kg: e.kg,
  }));

  // inputs[0] — sorting_items (precomputed_sorting scalar). avoided=40, gen=10,
  // net=30, ratio=4.
  const sortingTier2Rows = [
    { avoided_emissions: 25, canvas_id: CANVAS_ID, id: 's1', total_program_emissions_kg: 6 },
    { avoided_emissions: 15, canvas_id: CANVAS_ID, id: 's2', total_program_emissions_kg: 4 },
  ];
  const sortingTier2Columns = ['avoided_emissions', 'canvas_id', 'id', 'total_program_emissions_kg'];
  const tier2Csv = rowsToCanonicalCsv(sortingTier2Rows, sortingTier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);
  const tier1Rows = sortingTier2Rows.map((r) => ({
    avoided_emissions: r.avoided_emissions,
    id: r.id,
    total_program_emissions_kg: r.total_program_emissions_kg,
  }));
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, ['avoided_emissions', 'id', 'total_program_emissions_kg']);

  const metrics = {
    programme_id: PROGRAMME_ID,
    premium_pathway_rate: 0,
    net_carbon_impact_kg: 30,
    carbon_payback_ratio: 4,
    transaction_count: 0,
    data_status: 'measured',
    metrics_source: 'precomputed_sorting',
    period: null,
    outcomes_by_r_strategy: outcomesByRStrategy,
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(metrics));

  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [
      {
        dataset: 'sorting_items',
        row_count: sortingTier2Rows.length,
        hash: tier2Hash,
        columns: sortingTier2Columns,
        period_start: null,
        period_end: null,
      },
      {
        dataset: 'enhanced_transactions',
        row_count: pathwayRows.length,
        hash: pathwayHash,
        columns: pathwayColumns,
        period_start: null,
        period_end: null,
      },
    ],
    output: {
      metrics_hash: metricsHash,
      metrics_source: 'precomputed_sorting',
      pathway_outputs: pathwayOutputs,
    },
    computation: {
      transform: TRANSFORM_V2,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  return { manifest, tier1Csv, tier2Csv, pathwayCsv, metrics };
}

/**
 * Lying-producer variant of the v2 fixture (BRIEFING AC1 — the attack the
 * pathway recompute exists to catch). Everything binds correctly — manifest
 * signature, inputs[1] hash, metrics hash, scalar recompute — EXCEPT the signed
 * `pathway_outputs[]` block, whose first entry's kg is inflated BEFORE signing.
 * So the signature is valid over a block that disagrees with the honest inputs[1]
 * CSV. A Tier 2 recompute from that CSV must therefore diverge →
 * MISMATCH(pathway_recomputation), distinct from a scalar mismatch (D3).
 */
async function buildV2PathwayMismatchFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  const honest = await buildV2PathwayFixture(privateJwk, kid);
  const honestBlock = honest.manifest.output.pathway_outputs!;
  // Inflate the first entry's kg by 5 — beyond the 4dp tolerance.
  const lyingBlock = honestBlock.map((e, i) => (i === 0 ? { ...e, kg: e.kg + 5 } : { ...e }));

  const body: Omit<ComputationManifest, 'signature'> = {
    version: honest.manifest.version,
    programme_id: honest.manifest.programme_id,
    canvas_id: honest.manifest.canvas_id,
    published_version: honest.manifest.published_version,
    computed_at: honest.manifest.computed_at,
    inputs: honest.manifest.inputs,
    output: { ...honest.manifest.output, pathway_outputs: lyingBlock },
    computation: honest.manifest.computation,
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  return {
    manifest: { ...body, signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig } },
    tier1Csv: honest.tier1Csv,
    tier2Csv: honest.tier2Csv,
    pathwayCsv: honest.pathwayCsv,
    metrics: honest.metrics,
  };
}

/**
 * v3.0.0 fixture (BUILD_MetricsHash_Embedded_Projection_v0_1 §4.2 locking test).
 *
 * metrics_hash binds the EMBEDDED output.metrics canonical projection — not the
 * endpoint-served metrics view. To prove self-containment + endpoint-decoupling,
 * the embedded projection and the endpoint `metrics` (the Fixture.metrics that
 * becomes body.metrics at fetch time) are DELIBERATELY DIFFERENT objects:
 *   - embedded: the 12-field projection, compliance as the literal "[]" string;
 *   - endpoint: the richer presentation view (parsed compliance [], extra
 *     measurement_* / data_provenance keys, programme_id + metrics_source).
 * So a pre-v3 verifier (hashing body.metrics) would MISMATCH; the v3 branch
 * verifies metrics_hash from the embedded copy and reports the endpoint divergence
 * as a soft presentation-drift note. Scalar recompute at Tier 2 still reproduces
 * net_carbon_impact_kg=12 / carbon_payback_ratio=3 against the bound projection.
 */
async function buildV3EmbeddedMetricsFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  // precomputed_sorting inputs — avoided=18, generated=6, net=12, ratio=3.
  const sortingTier2Rows = [
    { avoided_emissions: 10, canvas_id: CANVAS_ID, id: 's1', total_program_emissions_kg: 4 },
    { avoided_emissions: 8, canvas_id: CANVAS_ID, id: 's2', total_program_emissions_kg: 2 },
  ];
  const sortingTier2Columns = ['avoided_emissions', 'canvas_id', 'id', 'total_program_emissions_kg'];
  const tier2Csv = rowsToCanonicalCsv(sortingTier2Rows, sortingTier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);
  const tier1Rows = sortingTier2Rows.map((r) => ({
    avoided_emissions: r.avoided_emissions,
    id: r.id,
    total_program_emissions_kg: r.total_program_emissions_kg,
  }));
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, ['avoided_emissions', 'id', 'total_program_emissions_kg']);

  // The embedded canonical projection (the 12 GATE-0 fields). This is the
  // metrics_hash preimage — it travels INSIDE the signed body.
  const embeddedMetrics = {
    avg_life_extension_months: null,
    carbon_payback_ratio: 3,
    net_carbon_impact_kg: 12,
    premium_pathway_rate: 0,
    repair_success_rate: null,
    transaction_count: 0,
    data_status: 'measured',
    period_start: null,
    period_end: null,
    compliance: '[]',
    emissions_methodology: null,
    methodology_scope: null,
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(embeddedMetrics));

  // The endpoint-served presentation view — intentionally a DIFFERENT object so
  // hashing it would NOT reproduce metrics_hash (endpoint-decoupling proof).
  const endpointMetrics = {
    programme_id: PROGRAMME_ID,
    metrics_source: 'precomputed_sorting',
    premium_pathway_rate: 0,
    net_carbon_impact_kg: 12,
    carbon_payback_ratio: 3,
    transaction_count: 0,
    data_status: 'measured',
    period: null,
    compliance: [],
    measurement_platform: 'Circulr Measurement Platform',
    measurement_scope: 'scope_3',
    data_provenance: 'measured',
  };

  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [{
      dataset: 'sorting_items',
      row_count: sortingTier2Rows.length,
      hash: tier2Hash,
      columns: sortingTier2Columns,
      period_start: null,
      period_end: null,
    }],
    output: {
      metrics_hash: metricsHash,
      metrics_source: 'precomputed_sorting',
      metrics: embeddedMetrics,
    },
    computation: {
      transform: TRANSFORM_V3,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  return { manifest, tier1Csv, tier2Csv, metrics: endpointMetrics };
}

const TRANSFORM_V31 = {
  function_id: 'circulr.publish-to-passport.programme-metrics',
  function_version: '3.1.0',
  function_url: 'https://circulrdesigner.circulr.ai/transforms/circulr.publish-to-passport.programme-metrics/3.1.0/manifest.json',
  description:
    'Programme metrics computation pipeline for au.com.auspost.sustainability §7-conformant manifests. ' +
    'v3.1.0 computes the scalar metrics over per-row 4dp-canonicalised (roundHalfEven) input values, matching the ' +
    'bound Tier-2 CSV, so a verifier reproduces them exactly (round-then-sum, not sum-then-round).',
};

/**
 * v3.1.0 fixture (BUILD_Metric_Recompute_Fidelity_v0_1 locking test). canonical_pipeline
 * with sub-4dp per-row co2e_kg so that round-then-sum ≠ sum-then-round. The producer
 * (v3.1.0) canonicalises each row to 4dp BEFORE summing — exactly the values the bound
 * Tier-2 CSV carries — so the verifier (which sums the 4dp CSV rows) reproduces the metric
 * EXACTLY. A pre-3.1.0 manifest (sum full precision, then round) would bind a different
 * net_carbon_impact_kg and MISMATCH here. Embeds output.metrics (inherited from 3.0.0).
 */
async function buildV31CanonicalFixture(privateJwk: JsonWebKey, kid: string): Promise<Fixture> {
  const round4 = (n: number) => Math.round(n * 10000) / 10000; // matches source + verifier round4

  // Full-precision rows: 34.68411 (avoided ×2), 193.02464 (processing ×2).
  // CSV serialiser rounds each cell to 4dp → 34.6841, 193.0246.
  const tier2Rows = [
    { co2e_kg: 34.68411, co2e_type: 'avoided', emission_factor_id: 'ef1', emission_factor_value: 1.15, id: 'r1', material_flow_record_id: 'm1', quantity_kg: 30.1601 },
    { co2e_kg: 34.68411, co2e_type: 'avoided', emission_factor_id: 'ef1', emission_factor_value: 1.15, id: 'r2', material_flow_record_id: 'm2', quantity_kg: 30.1601 },
    { co2e_kg: 193.02464, co2e_type: 'processing', emission_factor_id: 'ef2', emission_factor_value: 6.4, id: 'r3', material_flow_record_id: 'm1', quantity_kg: 30.1601 },
    { co2e_kg: 193.02464, co2e_type: 'processing', emission_factor_id: 'ef2', emission_factor_value: 6.4, id: 'r4', material_flow_record_id: 'm2', quantity_kg: 30.1601 },
  ];
  const tier2Columns = ['co2e_kg', 'co2e_type', 'emission_factor_id', 'emission_factor_value', 'id', 'material_flow_record_id', 'quantity_kg'];
  const tier2Csv = rowsToCanonicalCsv(tier2Rows, tier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);
  const tier1Rows = tier2Rows.map((r) => ({ co2e_kg: r.co2e_kg, co2e_type: r.co2e_type, id: r.id }));
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, ['co2e_kg', 'co2e_type', 'id']);

  // v3.1.0 metric: canonicalise each row to 4dp, accumulate, then round4 the aggregate.
  let avoided = 0, generated = 0;
  for (const r of tier2Rows) {
    const c = roundHalfEvenLocal(r.co2e_kg, 4);
    if (r.co2e_type === 'avoided') avoided += c; else generated += c;
  }
  const net = round4(avoided - generated);                          // -316.681 (round-then-sum)
  const ratio = round4(generated > 0 ? avoided / generated : 0);    // 0.1797

  const embeddedMetrics = {
    avg_life_extension_months: null,
    carbon_payback_ratio: ratio,
    net_carbon_impact_kg: net,
    premium_pathway_rate: 0,
    repair_success_rate: null,
    transaction_count: 0,
    data_status: 'measured',
    period_start: null,
    period_end: null,
    compliance: '[]',
    emissions_methodology: null,
    methodology_scope: null,
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(embeddedMetrics));

  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [{
      dataset: 'material_flow_co2e',
      row_count: tier2Rows.length,
      hash: tier2Hash,
      columns: tier2Columns,
      period_start: null,
      period_end: null,
    }],
    output: {
      metrics_hash: metricsHash,
      metrics_source: 'canonical_pipeline',
      metrics: embeddedMetrics,
    },
    computation: {
      transform: TRANSFORM_V31,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  // Endpoint serves the same embedded projection (no drift) — focus is metric_recomputation.
  return { manifest, tier1Csv, tier2Csv, metrics: embeddedMetrics };
}

const TRANSFORM_V41 = {
  function_id: 'circulr.publish-to-passport.programme-metrics',
  function_version: '4.1.0',
  function_url: 'https://circulrdesigner.circulr.ai/transforms/circulr.publish-to-passport.programme-metrics/4.1.0/manifest.json',
  description:
    'Programme metrics computation pipeline for au.com.auspost.sustainability §7-conformant manifests. ' +
    'v4.1.0 credits co2e_type=displacement as an avoided benefit in the canonical_pipeline scalar metrics (SPEC §Fork-3).',
};

/**
 * Displacement net-sign fixtures (SPEC_CirculrVerify_Reuse_Recompute Arm A). A canonical_pipeline
 * manifest carrying a co2e_type='displacement' row, netted per the version's signed convention:
 *   - creditDisplacement=true  (function_version >= 4.1.0): displacement is a benefit → net = (10+105) - 20 = 95
 *   - creditDisplacement=false (archived pre-4.1.0):         displacement is a burden  → net = 10 - (105+20) = -115
 * Both must VERIFY GREEN — each reproduces the convention its manifest was signed under. The v3.1.0
 * (burden) variant is the ARCHIVAL REGRESSION LOCK proving the verifier's version gate (creditDisplacement
 * = manifestMajorVersion >= 4) does not retroactively break archived displacement manifests.
 */
async function buildDisplacementFixture(
  privateJwk: JsonWebKey,
  kid: string,
  transform: typeof TRANSFORM_V41,
  creditDisplacement: boolean,
): Promise<Fixture> {
  const round4 = (n: number) => Math.round(n * 10000) / 10000;
  const tier2Rows = [
    { co2e_kg: 10, co2e_type: 'avoided', emission_factor_id: 'ef1', emission_factor_value: 1.15, id: 'r1', material_flow_record_id: 'm1', quantity_kg: 8.7 },
    { co2e_kg: 105, co2e_type: 'displacement', emission_factor_id: 'ef3', emission_factor_value: 21.0, id: 'r2', material_flow_record_id: 'm2', quantity_kg: 0 },
    { co2e_kg: 20, co2e_type: 'processing', emission_factor_id: 'ef2', emission_factor_value: 6.4, id: 'r3', material_flow_record_id: 'm1', quantity_kg: 3.1 },
  ];
  const tier2Columns = ['co2e_kg', 'co2e_type', 'emission_factor_id', 'emission_factor_value', 'id', 'material_flow_record_id', 'quantity_kg'];
  const tier2Csv = rowsToCanonicalCsv(tier2Rows, tier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);
  const tier1Rows = tier2Rows.map((r) => ({ co2e_kg: r.co2e_kg, co2e_type: r.co2e_type, id: r.id }));
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, ['co2e_kg', 'co2e_type', 'id']);

  // Net per the signed convention: displacement credited (benefit) iff creditDisplacement.
  let avoided = 0, generated = 0;
  for (const r of tier2Rows) {
    const c = roundHalfEvenLocal(r.co2e_kg, 4);
    const isBenefit = r.co2e_type === 'avoided' || (creditDisplacement && r.co2e_type === 'displacement');
    if (isBenefit) avoided += c; else generated += c;
  }
  const net = round4(avoided - generated);
  const ratio = round4(generated > 0 ? avoided / generated : 0);

  const embeddedMetrics = {
    avg_life_extension_months: null,
    carbon_payback_ratio: ratio,
    net_carbon_impact_kg: net,
    premium_pathway_rate: 0,
    repair_success_rate: null,
    transaction_count: 0,
    data_status: 'measured',
    period_start: null,
    period_end: null,
    compliance: '[]',
    emissions_methodology: null,
    methodology_scope: null,
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(embeddedMetrics));

  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [{
      dataset: 'material_flow_co2e',
      row_count: tier2Rows.length,
      hash: tier2Hash,
      columns: tier2Columns,
      period_start: null,
      period_end: null,
    }],
    output: {
      metrics_hash: metricsHash,
      metrics_source: 'canonical_pipeline',
      metrics: embeddedMetrics,
    },
    computation: {
      transform,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  return { manifest, tier1Csv, tier2Csv, metrics: embeddedMetrics };
}

const TRANSFORM_V5 = {
  function_id: 'circulr.publish-to-passport.programme-metrics',
  function_version: '5.0.0',
  function_url: 'https://circulrdesigner.circulr.ai/transforms/circulr.publish-to-passport.programme-metrics/5.0.0/manifest.json',
  description:
    'Programme metrics computation pipeline for au.com.auspost.sustainability §7-conformant manifests. ' +
    'v5.0.0 binds quantity_units into the canonical_pipeline inputs[0] projection so a verifier reproduces reuse displacement carbon (quantity_units × displacement_rate_applied × emission_factor_value).',
};

/**
 * v5.0.0 reuse Input Integrity fixtures (SPEC_CirculrVerify_Reuse_Recompute Arm B). 11-column
 * canonical_pipeline Tier-2 with a displacement row carrying quantity_units. Honest:
 * co2e_kg = quantity_units × displacement_rate_applied × emission_factor_value (10 × 0.5 × 21 = 105)
 * → reuse_basis_recomputation passes → Input Integrity for reuse. Tampered: co2e_kg disagrees
 * (200 ≠ 105) → reuse_basis_recomputation MISMATCH (proves the check bites). Both credit displacement
 * in the net (5.0.0 ⇒ major ≥ 4), and metric_recomputation reproduces the net from the rows (so the
 * tampered fixture fails specifically at reuse_basis_recomputation, not earlier).
 */
async function buildReuseFixture(privateJwk: JsonWebKey, kid: string, opts: { tamper: boolean }): Promise<Fixture> {
  const round4 = (n: number) => Math.round(n * 10000) / 10000;
  const dispCo2e = opts.tamper ? 200 : 105; // honest 105 = 10 × 0.5 × 21
  const tier2Rows = [
    { calculation_basis: 'per_item', co2e_kg: dispCo2e, co2e_type: 'displacement', displacement_rate_applied: 0.5, emission_factor_id: 'ef_disp', emission_factor_value: 21.0, id: 'r1', loop_type_applied: 'reuse', material_flow_record_id: 'm1', quantity_kg: 0, quantity_units: 10 },
    { calculation_basis: 'per_kg', co2e_kg: 20, co2e_type: 'processing', displacement_rate_applied: null, emission_factor_id: 'ef2', emission_factor_value: 6.4, id: 'r2', loop_type_applied: 'reuse', material_flow_record_id: 'm1', quantity_kg: 3.1, quantity_units: null },
  ];
  const tier2Columns = ['calculation_basis', 'co2e_kg', 'co2e_type', 'displacement_rate_applied', 'emission_factor_id', 'emission_factor_value', 'id', 'loop_type_applied', 'material_flow_record_id', 'quantity_kg', 'quantity_units'];
  const tier2Csv = rowsToCanonicalCsv(tier2Rows, tier2Columns);
  const tier2Hash = await sha256Hex(tier2Csv);
  const tier1Rows = tier2Rows.map((r) => ({ co2e_kg: r.co2e_kg, co2e_type: r.co2e_type, id: r.id }));
  const tier1Csv = rowsToCanonicalCsv(tier1Rows, ['co2e_kg', 'co2e_type', 'id']);

  // 5.0.0 credits displacement (major ≥ 4). net = displacement(credited) − processing.
  let avoided = 0, generated = 0;
  for (const r of tier2Rows) {
    const c = roundHalfEvenLocal(r.co2e_kg, 4);
    const isBenefit = r.co2e_type === 'avoided' || r.co2e_type === 'displacement';
    if (isBenefit) avoided += c; else generated += c;
  }
  const net = round4(avoided - generated);
  const ratio = round4(generated > 0 ? avoided / generated : 0);

  const embeddedMetrics = {
    avg_life_extension_months: null,
    carbon_payback_ratio: ratio,
    net_carbon_impact_kg: net,
    premium_pathway_rate: 0,
    repair_success_rate: null,
    transaction_count: 0,
    data_status: 'measured',
    period_start: null,
    period_end: null,
    compliance: '[]',
    emissions_methodology: null,
    methodology_scope: null,
  };
  const metricsHash = await sha256Hex(canonicalJsonStringify(embeddedMetrics));

  const body: Omit<ComputationManifest, 'signature'> = {
    version: '1.0',
    programme_id: PROGRAMME_ID,
    canvas_id: CANVAS_ID,
    published_version: PUBLISHED_VERSION,
    computed_at: COMPUTED_AT,
    inputs: [{
      dataset: 'material_flow_co2e',
      row_count: tier2Rows.length,
      hash: tier2Hash,
      columns: tier2Columns,
      period_start: null,
      period_end: null,
    }],
    output: {
      metrics_hash: metricsHash,
      metrics_source: 'canonical_pipeline',
      metrics: embeddedMetrics,
    },
    computation: {
      transform: TRANSFORM_V5,
      emission_factors_hash: 'deadbeef',
      rounding_rule: 'ROUND_HALF_EVEN_4DP',
      null_handling: 'null_as_zero',
    },
  };
  const sig = await signManifest(canonicalJsonStringify(body), privateJwk);
  const manifest: ComputationManifest = {
    ...body,
    signature: { algorithm: 'ES256', public_key_id: kid, public_key_url: KEY_URL, value: sig },
  };
  return { manifest, tier1Csv, tier2Csv, metrics: embeddedMetrics };
}

// =============================================================================
// Entry
// =============================================================================

async function main(): Promise<void> {
  const outDir = __dirname;
  await mkdir(outDir, { recursive: true });

  // Reuse the committed keypair if present, so adding a fixture doesn't re-key and churn every
  // existing manifest's signature. Only mint a fresh keypair on first run (no keys.json yet).
  let privateJwk: JsonWebKey;
  let publicJwk: JsonWebKey;
  let kid: string;
  const keysPath = join(outDir, 'keys.json');
  try {
    const existing = JSON.parse(await readFile(keysPath, 'utf8')) as { privateJwk: JsonWebKey; publicJwk: JsonWebKey; kid: string };
    ({ privateJwk, publicJwk, kid } = existing);
  } catch {
    ({ privateJwk, publicJwk, kid } = await generateKeypair());
    await writeFile(keysPath, JSON.stringify({ privateJwk, publicJwk, kid, key_url: KEY_URL }, null, 2));
  }

  const canonical = await buildCanonicalPipelineFixture(privateJwk, kid);
  const journeys = await buildEnhancedJourneysFixture(privateJwk, kid);
  const sorting = await buildPrecomputedSortingFixture(privateJwk, kid);
  const design = await buildDesigntimeEstimationFixture(privateJwk, kid);
  const ii = await buildInputIntegrityFixture(privateJwk, kid);
  const v2 = await buildV2PathwayFixture(privateJwk, kid);
  const v2Mismatch = await buildV2PathwayMismatchFixture(privateJwk, kid);
  const v3 = await buildV3EmbeddedMetricsFixture(privateJwk, kid);
  const v31 = await buildV31CanonicalFixture(privateJwk, kid);
  const v41disp = await buildDisplacementFixture(privateJwk, kid, TRANSFORM_V41, true);
  const v31disp = await buildDisplacementFixture(privateJwk, kid, TRANSFORM_V31, false);
  const v5reuse = await buildReuseFixture(privateJwk, kid, { tamper: false });
  const v5reuseTampered = await buildReuseFixture(privateJwk, kid, { tamper: true });

  const writes: Array<[string, string]> = [
    ['manifest_canonical_pipeline.json', JSON.stringify(canonical.manifest, null, 2)],
    ['tier1_canonical_pipeline.csv', canonical.tier1Csv],
    ['tier2_canonical_pipeline.csv', canonical.tier2Csv ?? ''],
    ['metrics_canonical_pipeline.json', JSON.stringify(canonical.metrics, null, 2)],

    ['manifest_enhanced_journeys.json', JSON.stringify(journeys.manifest, null, 2)],
    ['tier1_enhanced_journeys.csv', journeys.tier1Csv],
    ['metrics_enhanced_journeys.json', JSON.stringify(journeys.metrics, null, 2)],

    ['manifest_precomputed_sorting.json', JSON.stringify(sorting.manifest, null, 2)],
    ['tier1_precomputed_sorting.csv', sorting.tier1Csv],
    ['metrics_precomputed_sorting.json', JSON.stringify(sorting.metrics, null, 2)],

    ['manifest_designtime_estimation.json', JSON.stringify(design.manifest, null, 2)],
    ['tier1_designtime_estimation.csv', design.tier1Csv],
    ['metrics_designtime_estimation.json', JSON.stringify(design.metrics, null, 2)],

    ['manifest_input_integrity.json', JSON.stringify(ii.manifest, null, 2)],

    ['manifest_v2_pathway.json', JSON.stringify(v2.manifest, null, 2)],
    ['tier1_v2_pathway.csv', v2.tier1Csv],
    ['tier2_v2_pathway.csv', v2.tier2Csv ?? ''],
    ['pathway_v2_pathway.csv', v2.pathwayCsv ?? ''],
    ['metrics_v2_pathway.json', JSON.stringify(v2.metrics, null, 2)],

    // Lying-producer variant: same bound inputs, signed block disagrees.
    ['manifest_v2_pathway_mismatch.json', JSON.stringify(v2Mismatch.manifest, null, 2)],
    ['tier1_v2_pathway_mismatch.csv', v2Mismatch.tier1Csv],
    ['tier2_v2_pathway_mismatch.csv', v2Mismatch.tier2Csv ?? ''],
    ['pathway_v2_pathway_mismatch.csv', v2Mismatch.pathwayCsv ?? ''],
    ['metrics_v2_pathway_mismatch.json', JSON.stringify(v2Mismatch.metrics, null, 2)],

    // v3.0.0 — embedded output.metrics; endpoint metrics deliberately divergent.
    ['manifest_v3_embedded.json', JSON.stringify(v3.manifest, null, 2)],
    ['tier1_v3_embedded.csv', v3.tier1Csv],
    ['tier2_v3_embedded.csv', v3.tier2Csv ?? ''],
    ['metrics_v3_embedded.json', JSON.stringify(v3.metrics, null, 2)],

    // v3.1.0 — sub-4dp rows; round-then-sum metric reproducible from the 4dp CSV.
    ['manifest_v31_canonical.json', JSON.stringify(v31.manifest, null, 2)],
    ['tier1_v31_canonical.csv', v31.tier1Csv],
    ['tier2_v31_canonical.csv', v31.tier2Csv ?? ''],
    ['metrics_v31_canonical.json', JSON.stringify(v31.metrics, null, 2)],

    ['manifest_v41_displacement.json', JSON.stringify(v41disp.manifest, null, 2)],
    ['tier1_v41_displacement.csv', v41disp.tier1Csv],
    ['tier2_v41_displacement.csv', v41disp.tier2Csv ?? ''],
    ['metrics_v41_displacement.json', JSON.stringify(v41disp.metrics, null, 2)],

    ['manifest_v31_displacement.json', JSON.stringify(v31disp.manifest, null, 2)],
    ['tier1_v31_displacement.csv', v31disp.tier1Csv],
    ['tier2_v31_displacement.csv', v31disp.tier2Csv ?? ''],
    ['metrics_v31_displacement.json', JSON.stringify(v31disp.metrics, null, 2)],

    ['manifest_v5_reuse.json', JSON.stringify(v5reuse.manifest, null, 2)],
    ['tier1_v5_reuse.csv', v5reuse.tier1Csv],
    ['tier2_v5_reuse.csv', v5reuse.tier2Csv ?? ''],
    ['metrics_v5_reuse.json', JSON.stringify(v5reuse.metrics, null, 2)],

    ['manifest_v5_reuse_tampered.json', JSON.stringify(v5reuseTampered.manifest, null, 2)],
    ['tier1_v5_reuse_tampered.csv', v5reuseTampered.tier1Csv],
    ['tier2_v5_reuse_tampered.csv', v5reuseTampered.tier2Csv ?? ''],
    ['metrics_v5_reuse_tampered.json', JSON.stringify(v5reuseTampered.metrics, null, 2)],
  ];

  for (const [name, body] of writes) {
    await writeFile(join(outDir, name), body);
  }

  console.log(`Wrote ${writes.length} fixture files + keys.json to ${outDir}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
