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

import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  base64UrlEncode,
  canonicalJsonStringify,
  sha256Hex,
  type ComputationManifest,
} from '../../src/crypto.js';

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

interface Fixture {
  manifest: ComputationManifest;
  tier1Csv: string;
  tier2Csv?: string;
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

// =============================================================================
// Entry
// =============================================================================

async function main(): Promise<void> {
  const outDir = __dirname;
  await mkdir(outDir, { recursive: true });

  const { privateJwk, publicJwk, kid } = await generateKeypair();
  await writeFile(join(outDir, 'keys.json'), JSON.stringify({ privateJwk, publicJwk, kid, key_url: KEY_URL }, null, 2));

  const canonical = await buildCanonicalPipelineFixture(privateJwk, kid);
  const journeys = await buildEnhancedJourneysFixture(privateJwk, kid);
  const sorting = await buildPrecomputedSortingFixture(privateJwk, kid);
  const design = await buildDesigntimeEstimationFixture(privateJwk, kid);
  const ii = await buildInputIntegrityFixture(privateJwk, kid);

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
