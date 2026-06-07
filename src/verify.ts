// src/verify.ts
//
// Orchestrator for the Independent Reproduction Protocol (au.com.auspost.sustainability §7.4).
// Returns a discriminated VerifyResult union.
//
// Implements spec §5.3 steps 1-11.

import { parse as parseCsv } from 'csv-parse/sync';
import {
  canonicalJsonStringify,
  importEs256VerifyingKey,
  manifestSigningBody,
  sha256Hex,
  verifyES256,
  type ClaimLevel,
  type DatasetHash,
  type IndependenceCheck,
  type MetricsSource,
} from './crypto.js';
import {
  FetchError,
  fetchJwk,
  fetchPathwayCsv,
  fetchProgrammeManifest,
  fetchTier1Csv,
  fetchTier2Csv,
} from './fetch.js';
import { metricsApproxEqual, recomputeForSource, type RecomputedMetrics } from './recompute.js';
import {
  comparePathwayBlock,
  compareL2Projection,
  recomputePathwayOutputs,
  type PathwayOutput,
} from './pathway.js';

// =============================================================================
// Public types
// =============================================================================

export interface VerifyArgs {
  endpoint: string;
  programmeId: string;
  tier: 1 | 2;
  supabaseToken?: string;
  publishedVersion?: number;
  fetcher?: typeof fetch;
}

export type CheckName =
  | 'manifest_signature'
  | 'metrics_hash_binding'
  | 'tier1_input_aggregate'
  | 'tier2_input_hash'
  | 'metric_recomputation'
  | 'pathway_input_hash'
  | 'pathway_recomputation';

/**
 * The pathway breakdown verdict — reported SEPARATELY from the scalar metric
 * verdict (BRIEFING AC5 / AC20 honest-claim). The verifier never folds an
 * unestablished pathway result into the scalar claim.
 *
 *  - `verified` — the (r_strategy, loop_type) block recomputed from the bound
 *    inputs[1] CSV and matched the signed block (and, where present, the L2
 *    projection).
 *  - `mismatch` — recompute or projection diverged; the overall result is a
 *    MISMATCH(pathway_recomputation), distinct from a scalar mismatch (D3).
 *  - `not_verifiable_yet` — the block is signature-bound but was not
 *    independently recomputed in this run (no block at all, Tier 1, or the
 *    pathway input was unreachable). Does NOT fail the scalar result.
 */
export interface PathwayVerdict {
  status: 'verified' | 'mismatch' | 'not_verifiable_yet';
  /** not_verifiable_yet reason: no_block | tier1 | no_pathway_url | fetch_failed | no_input_hash. */
  reason?: string;
  /** True when a composite L2 outcomes_by_r_strategy projection was present and matched the block. */
  projection_checked?: boolean;
  detail?: string;
}

export interface PassedCheck {
  name: CheckName;
  passed: true;
  /** Algorithm or per-check metadata, surfaced in JSON output. */
  algorithm?: string;
  tolerance_dp?: number;
  tier?: 1 | 2;
  expected?: string;
  actual?: string;
}

export interface FailedCheck {
  name: CheckName;
  passed: false;
  detail: string;
  algorithm?: string;
  tolerance_dp?: number;
  tier?: 1 | 2;
  expected?: string;
  actual?: string;
}

export type Check = PassedCheck | FailedCheck;

export interface VerifyContext {
  programme_id: string;
  published_version: number;
  manifest_version: '1.0';
  computed_at: string;
  metrics_source: string;
  public_key_id: string;
  public_key_url: string;
  manifest_claim_level: ClaimLevel;
  independence_check: IndependenceCheck | null;
  manifest_source: 'archive' | 'rest_jsonb';
  checks: Check[];
  recomputed?: RecomputedMetrics;
  published_metrics?: Record<string, unknown>;
  /**
   * BUILD_MetricsHash_Embedded_Projection_v0_1 — set when a legacy (<3.0.0)
   * manifest's whole-row metrics_hash cannot be reproduced from the endpoint's
   * served metrics. This is EXPECTED by construction (the legacy preimage was the
   * full programme_metrics row, never the consumer view), so it degrades honestly
   * here rather than hard-failing the scalar claim (AC4).
   */
  metrics_hash_binding_note?: string;
  /**
   * Set on a v3.0.0+ manifest when the SELF-CONTAINED embedded binding verified
   * but the endpoint's served metrics serialise to a different hash — a soft
   * presentation-drift note, never a failure (the bound claim is the embedded
   * output.metrics, not the endpoint shape).
   */
  metrics_presentation_drift_note?: string;
  /** Canonical signing body — surfaced in --verbose. */
  canonical_body?: string;
  /** Pathway breakdown verdict — separate from the scalar claim (AC5). */
  pathway?: PathwayVerdict;
  /** The signed pathway_outputs[] block when present — surfaced in --verbose. */
  pathway_block?: PathwayOutput[];
}

export type VerifyResult =
  | {
      kind: 'verified';
      /** Claim established by the verifier side. Reports verifier-side, not manifest-declared. */
      claim: ClaimLevel;
      tier_run: 1 | 2;
      context: VerifyContext;
    }
  | {
      kind: 'mismatch';
      failed_at: CheckName;
      detail: string;
      tier_run: 1 | 2;
      context: VerifyContext;
    }
  | {
      kind: 'not_verifiable_yet';
      manifest_state: 'absent' | 'key_pending';
      detail: string;
      /** Best-effort published_version when known. */
      published_version?: number;
    }
  | {
      kind: 'archive_locked';
      existing_function_version: string;
      requested_function_version: string;
      detail: string;
    };

/**
 * Parse the MAJOR component of a transform function_version ("3.0.0" → 3). Used
 * to branch metrics_hash_binding between the legacy whole-row binding (<3.0.0)
 * and the v3.0.0+ embedded, self-contained output.metrics projection. Returns 0
 * for an unparseable/missing version (treated as legacy — the conservative
 * branch that never hard-fails on an unreproducible binding).
 */
export function manifestMajorVersion(version: string | undefined): number {
  if (!version) return 0;
  const major = Number.parseInt(version.split('.')[0] ?? '', 10);
  return Number.isFinite(major) ? major : 0;
}

// =============================================================================
// Orchestration
// =============================================================================

export async function verify(args: VerifyArgs): Promise<VerifyResult> {
  const fetcher = args.fetcher ?? fetch;

  // Steps 1-3: fetch the manifest (REST + archive preference per AC7).
  let fetched;
  try {
    fetched = await fetchProgrammeManifest(args.endpoint, args.programmeId, args.publishedVersion, fetcher);
  } catch (e) {
    if (e instanceof FetchError && e.kind === 'manifest_absent') {
      return {
        kind: 'not_verifiable_yet',
        manifest_state: 'absent',
        detail: e.message,
      };
    }
    if (e instanceof FetchError && e.kind === 'manifest_key_pending') {
      return {
        kind: 'not_verifiable_yet',
        manifest_state: 'key_pending',
        detail: e.message,
      };
    }
    throw e;
  }

  const { manifest, source: manifestSource, tier1CsvUrl, tier2CsvUrl, pathwayCsvUrl } = fetched;
  const checks: Check[] = [];
  const context: VerifyContext = {
    programme_id: manifest.programme_id,
    published_version: manifest.published_version,
    manifest_version: manifest.version,
    computed_at: manifest.computed_at,
    metrics_source: manifest.output.metrics_source,
    public_key_id: manifest.signature.public_key_id,
    public_key_url: manifest.signature.public_key_url,
    manifest_claim_level: manifest.claim_level ?? 'aggregation_integrity',
    independence_check: manifest.independence_check ?? null,
    manifest_source: manifestSource,
    checks,
  };

  const canonicalBody = manifestSigningBody(manifest);
  context.canonical_body = canonicalBody;

  // Step 4-6: signature check.
  let jwk;
  try {
    jwk = await fetchJwk(
      manifest.signature.public_key_url,
      manifest.signature.public_key_id,
      fetcher,
    );
  } catch (e) {
    if (
      e instanceof FetchError &&
      (e.kind === 'jwk_not_found' || e.kind === 'jwk_key_id_missing')
    ) {
      const failed: FailedCheck = {
        name: 'manifest_signature',
        passed: false,
        algorithm: 'ES256',
        detail: `${e.message}. Did you point --endpoint at the right environment?`,
      };
      checks.push(failed);
      return {
        kind: 'mismatch',
        failed_at: 'manifest_signature',
        detail: failed.detail,
        tier_run: args.tier,
        context,
      };
    }
    throw e;
  }

  const verifyingKey = await importEs256VerifyingKey(jwk);
  const sigOk = await verifyES256(canonicalBody, manifest.signature.value, verifyingKey);
  if (!sigOk) {
    const detail =
      'ES256 verification of the canonical manifest body failed. Manifest may have been ' +
      'tampered with after signing.';
    checks.push({ name: 'manifest_signature', passed: false, algorithm: 'ES256', detail });
    return {
      kind: 'mismatch',
      failed_at: 'manifest_signature',
      detail,
      tier_run: args.tier,
      context,
    };
  }
  checks.push({ name: 'manifest_signature', passed: true, algorithm: 'ES256' });

  // Step 8: Tier 1 — aggregate-derived check on the recomputable subset.
  // Spec §5.3 step 8 reads as a hash comparison; the actual binding in the
  // source attaches the SHA-256 of the Tier-2-projected CSV to
  // `inputs[].hash` (not the Tier-1 CSV). The verifier's Tier-1 contract is
  // therefore: hash of REST `metrics` JSON binds; recompute from Tier 1
  // rows reproduces the recomputable subset of those values. See module
  // header in recompute.ts for the full rationale.
  if (!tier1CsvUrl) {
    const detail =
      'Endpoint did not advertise tier1_csv_url. The verifier cannot reach Tier 1 data without it. ' +
      'Upgrade the endpoint to surface storage URL hints, or run the verifier from a context that ' +
      'already has the Tier 1 CSV available.';
    checks.push({ name: 'tier1_input_aggregate', passed: false, tier: 1, detail });
    return {
      kind: 'mismatch',
      failed_at: 'tier1_input_aggregate',
      detail,
      tier_run: args.tier,
      context,
    };
  }

  let tier1Csv;
  try {
    tier1Csv = await fetchTier1Csv(tier1CsvUrl, fetcher);
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    checks.push({ name: 'tier1_input_aggregate', passed: false, tier: 1, detail });
    return {
      kind: 'mismatch',
      failed_at: 'tier1_input_aggregate',
      detail,
      tier_run: args.tier,
      context,
    };
  }

  const tier1Rows = parseCsv(tier1Csv, {
    columns: true,
    skip_empty_lines: true,
    cast: false,
  }) as Array<Record<string, unknown>>;

  // Step 9 (Tier 2 only): byte-hash Tier 2 CSV against manifest.inputs[].hash.
  // The Tier 2 column projection matches the manifest's `inputs[].columns`, so
  // the SHA-256 of the canonical Tier 2 CSV equals the manifest's `inputs[].hash`.
  let tier2Rows: Array<Record<string, unknown>> | null = null;
  if (args.tier === 2) {
    if (!args.supabaseToken) {
      const detail = '--tier 2 requires --supabase-token (programme-participant Supabase JWT).';
      checks.push({ name: 'tier2_input_hash', passed: false, tier: 2, detail });
      return {
        kind: 'mismatch',
        failed_at: 'tier2_input_hash',
        detail,
        tier_run: args.tier,
        context,
      };
    }
    if (!tier2CsvUrl) {
      const detail = 'Endpoint did not advertise tier2_csv_url; cannot perform Input Integrity check.';
      checks.push({ name: 'tier2_input_hash', passed: false, tier: 2, detail });
      return {
        kind: 'mismatch',
        failed_at: 'tier2_input_hash',
        detail,
        tier_run: args.tier,
        context,
      };
    }

    let tier2Csv;
    try {
      tier2Csv = await fetchTier2Csv(tier2CsvUrl, args.supabaseToken, fetcher);
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e);
      checks.push({ name: 'tier2_input_hash', passed: false, tier: 2, detail });
      return {
        kind: 'mismatch',
        failed_at: 'tier2_input_hash',
        detail,
        tier_run: args.tier,
        context,
      };
    }

    const tier2Hash = await sha256Hex(tier2Csv);
    const expectedHash = manifest.inputs[0]?.hash;
    if (!expectedHash) {
      const detail = 'Manifest has no inputs[0].hash to verify Tier 2 CSV against.';
      checks.push({ name: 'tier2_input_hash', passed: false, tier: 2, detail });
      return {
        kind: 'mismatch',
        failed_at: 'tier2_input_hash',
        detail,
        tier_run: args.tier,
        context,
      };
    }
    if (tier2Hash !== expectedHash) {
      const detail = `SHA-256 of Tier 2 CSV does not match manifest.inputs[0].hash.`;
      checks.push({
        name: 'tier2_input_hash',
        passed: false,
        tier: 2,
        expected: expectedHash,
        actual: tier2Hash,
        detail,
      });
      return {
        kind: 'mismatch',
        failed_at: 'tier2_input_hash',
        detail,
        tier_run: args.tier,
        context,
      };
    }
    checks.push({
      name: 'tier2_input_hash',
      passed: true,
      tier: 2,
      expected: expectedHash,
      actual: tier2Hash,
    });

    tier2Rows = parseCsv(tier2Csv, {
      columns: true,
      skip_empty_lines: true,
      cast: false,
    }) as Array<Record<string, unknown>>;
  }

  // Step 7 + 10: metrics hash binding + recompute.
  // The published `metrics` row in the REST response is what was canonicalised
  // and hashed at publish time. Re-fetch it via the same REST endpoint that
  // already gave us the manifest. We have it in scope from fetchProgrammeManifest's
  // body — but fetchProgrammeManifest returns only the manifest. Re-call the
  // REST endpoint here to grab `metrics` for the binding check.
  let publishedMetrics: Record<string, unknown> | null = null;
  try {
    const metricsResp = await fetcher(
      `${args.endpoint.replace(/\/$/, '')}/api/programme/${encodeURIComponent(args.programmeId)}/metrics?published_version=${manifest.published_version}`,
      { headers: { accept: 'application/json' } },
    );
    if (metricsResp.ok) {
      const body = (await metricsResp.json()) as { metrics?: Record<string, unknown> };
      publishedMetrics = body.metrics ?? null;
    }
  } catch {
    // Non-fatal; metrics-hash binding check just degrades.
  }

  // ===========================================================================
  // Pathway composite verification (v2.0.0 — BRIEFING_circulr_verify_Pathway_
  // Verification). Reported as a SEPARATE verdict from the scalar claim (AC5/AC20).
  //
  // Evaluated HERE — before the scalar metrics_hash / metric_recomputation checks —
  // so the pathway verdict is populated in `context.pathway` and reported even when
  // a scalar check subsequently mismatches. The pathway block is signature-bound
  // (manifest_signature passed above), so its authenticity is fully independent of
  // the scalar `metrics_hash` binding; the honest-claim model (AC20) requires the
  // pathway claim be reported on its own, never folded into or gated by the scalar
  // claim. (`verifyPathway` returns null for every not_verifiable_yet degrade and
  // only early-returns on a genuine MISMATCH(pathway_recomputation) — D3.)
  //
  // function_version awareness (item 3): the discriminator is the presence of
  // output.pathway_outputs — the v2.0.0 producer always populates it; archived
  // 1.0.0 manifests predate it. A missing block is honest not_verifiable_yet,
  // NOT a failure — archived 1.0.0 verification must not break (AC4).
  // ===========================================================================
  const pathwayBlock = manifest.output.pathway_outputs;
  const functionVersion = manifest.computation.transform.function_version;

  if (pathwayBlock === undefined) {
    context.pathway = {
      status: 'not_verifiable_yet',
      reason: 'no_block',
      detail:
        `Manifest function_version ${functionVersion} carries no output.pathway_outputs block; ` +
        `the pathway breakdown is not part of this manifest.`,
    };
  } else {
    context.pathway_block = pathwayBlock;
    const pathwayMismatch = await verifyPathway({
      tier: args.tier,
      supabaseToken: args.supabaseToken,
      pathwayCsvUrl,
      pathwayBlock,
      pathwayInput: manifest.inputs[1],
      publishedMetrics,
      checks,
      context,
      fetcher,
    });
    if (pathwayMismatch) return pathwayMismatch;
  }

  // ===========================================================================
  // metrics_hash_binding — function_version branch (BUILD_MetricsHash_Embedded_
  // Projection_v0_1). The discriminator is function_version >= 3.0.0 AND the
  // presence of the embedded output.metrics projection.
  //
  //  - v3.0.0+ (embedded): hash the SELF-CONTAINED output.metrics that travels
  //    inside the signature-bound body. metrics_hash MUST equal it — a mismatch
  //    is an internally-inconsistent signed body (a genuine integrity failure),
  //    not endpoint drift. No dependency on the endpoint serving a byte-identical
  //    shape. A divergent endpoint serialisation is a soft presentation note only.
  //  - <3.0.0 (legacy whole-row): the metrics_hash preimage was the full
  //    programme_metrics row, which the consumer endpoint never serves verbatim.
  //    A mismatch is therefore EXPECTED by construction — degrade honestly
  //    (note, not a hard fail) so archived manifests still verify (AC4). A match
  //    (e.g. faithfully-mirrored fixtures) still passes the check cleanly.
  //
  // `boundMetrics` is the authoritative metrics object the downstream recompute
  // then compares against: the embedded projection at v3+, else the endpoint view.
  // ===========================================================================
  const useEmbeddedBinding = manifestMajorVersion(functionVersion) >= 3 &&
    manifest.output.metrics != null;
  const embeddedMetrics = manifest.output.metrics ?? null;
  let boundMetrics: Record<string, unknown> | null = null;

  if (useEmbeddedBinding && embeddedMetrics) {
    const publishedHash = await sha256Hex(canonicalJsonStringify(embeddedMetrics));
    if (publishedHash !== manifest.output.metrics_hash) {
      const detail =
        `Embedded output.metrics does not hash to manifest.output.metrics_hash. ` +
        `The signed manifest body is internally inconsistent (output.metrics was mutated, ` +
        `or metrics_hash was computed over a different object).`;
      checks.push({
        name: 'metrics_hash_binding',
        passed: false,
        algorithm: 'SHA-256',
        expected: manifest.output.metrics_hash,
        actual: publishedHash,
        detail,
      });
      return {
        kind: 'mismatch',
        failed_at: 'metrics_hash_binding',
        detail,
        tier_run: args.tier,
        context: { ...context, published_metrics: embeddedMetrics },
      };
    }
    checks.push({
      name: 'metrics_hash_binding',
      passed: true,
      algorithm: 'SHA-256',
      expected: manifest.output.metrics_hash,
      actual: publishedHash,
    });
    boundMetrics = embeddedMetrics;
    context.published_metrics = embeddedMetrics;

    // Soft cross-check: does the endpoint's served view serialise to the same
    // hash? Drift is presentation-only and never fails the bound claim.
    if (publishedMetrics) {
      const endpointHash = await sha256Hex(canonicalJsonStringify(publishedMetrics));
      if (endpointHash !== manifest.output.metrics_hash) {
        context.metrics_presentation_drift_note =
          `Endpoint /metrics serialises to a different hash (${endpointHash}) than the embedded, ` +
          `signature-bound output.metrics (${manifest.output.metrics_hash}). The bound claim is the ` +
          `embedded projection; the endpoint shape is presentation only.`;
      }
    }
  } else if (publishedMetrics) {
    const publishedHash = await sha256Hex(canonicalJsonStringify(publishedMetrics));
    if (publishedHash === manifest.output.metrics_hash) {
      checks.push({
        name: 'metrics_hash_binding',
        passed: true,
        algorithm: 'SHA-256',
        expected: manifest.output.metrics_hash,
        actual: publishedHash,
      });
    } else {
      // Legacy whole-row binding — not consumer-reproducible by construction.
      // Degrade honestly (AC4): no failed check, no scalar mismatch.
      context.metrics_hash_binding_note =
        `function_version ${functionVersion} bound metrics_hash to the whole programme_metrics row, ` +
        `which the consumer endpoint does not serve verbatim — so this binding is not independently ` +
        `reproducible (expected for legacy manifests). The manifest signature and pathway block remain ` +
        `verified; only the scalar metrics_hash binding is not reproducible. Republish at v3.0.0+ for a ` +
        `self-contained, reproducible binding.`;
    }
    boundMetrics = publishedMetrics;
    context.published_metrics = publishedMetrics;
  }

  // Recompute the metric-driving values from the verified tier data.
  const recomputeSourceRows = tier2Rows ?? tier1Rows;
  const recomputed = recomputeForSource(
    manifest.output.metrics_source as MetricsSource,
    recomputeSourceRows,
  );
  context.recomputed = recomputed;

  // Compare against the bound metric values for each recomputable field. At
  // v3.0.0+ this is the embedded, signature-bound projection (so the recompute
  // confirms the SIGNED claim, not merely the endpoint view); at <3.0.0 it falls
  // back to the endpoint's served metrics.
  if (boundMetrics) {
    for (const field of recomputed.recomputed_fields) {
      const published = Number(boundMetrics[field] ?? 0);
      const computed = recomputed[field];
      if (!metricsApproxEqual(published, computed)) {
        const detail =
          `Recomputed ${field} (${computed}) does not match published value (${published}) ` +
          `at 4dp tolerance. ` +
          (args.tier === 1
            ? `Tier 1 is a projection; if the source used Tier-2-only data this is expected — ` +
              `re-run with --tier 2 --supabase-token to confirm.`
            : `Tier 2 reproduction failed — the manifest's published metrics cannot be reproduced ` +
              `from the verified Tier 2 inputs under the declared transform.`);
        const check: FailedCheck = {
          name: 'metric_recomputation',
          passed: false,
          tolerance_dp: 4,
          expected: String(published),
          actual: String(computed),
          detail,
        };
        checks.push(check);
        return {
          kind: 'mismatch',
          failed_at: 'metric_recomputation',
          detail,
          tier_run: args.tier,
          context,
        };
      }
    }
  }
  checks.push({
    name: 'metric_recomputation',
    passed: true,
    tolerance_dp: 4,
  });

  // Step 11: report claim.
  //   --tier 1 → always Aggregation Integrity
  //   --tier 2 → Input Integrity iff the recompute succeeded against the raw inputs
  // (Per spec §3.3 the verifier reports what it actually established, NOT what
  // the manifest declares. A Tier 1 verifier reports Aggregation Integrity even
  // when manifest.claim_level === 'input_integrity'.)
  const claim: ClaimLevel = args.tier === 2 ? 'input_integrity' : 'aggregation_integrity';
  return {
    kind: 'verified',
    claim,
    tier_run: args.tier,
    context,
  };
}

// =============================================================================
// Pathway composite verification (BRIEFING items 1-4)
// =============================================================================

interface PathwayVerifyArgs {
  tier: 1 | 2;
  supabaseToken?: string;
  pathwayCsvUrl?: string;
  pathwayBlock: PathwayOutput[];
  pathwayInput: DatasetHash | undefined;
  publishedMetrics: Record<string, unknown> | null;
  checks: Check[];
  context: VerifyContext;
  fetcher: typeof fetch;
}

/**
 * Recompute and confirm the signed `pathway_outputs[]` block from the bound
 * inputs[1] CSV. Mutates `context.pathway` (and pushes pathway checks) in place.
 *
 * Returns a MISMATCH VerifyResult when the pathway recompute, the inputs[1]
 * hash, or the L2 projection diverges (D3 — distinct from a scalar mismatch).
 * Returns `null` to let the caller proceed to the scalar `verified` result —
 * including every not_verifiable_yet degrade (no Tier 2 access, no pathway URL,
 * fetch failure): a pathway that cannot be independently recomputed must not
 * fail the scalar claim (AC5/AC20).
 */
async function verifyPathway(a: PathwayVerifyArgs): Promise<VerifyResult | null> {
  const { pathwayBlock, context, checks } = a;

  // Independent recompute is a Tier 2 capability — inputs[1] is RLS-restricted.
  if (a.tier !== 2 || !a.supabaseToken) {
    context.pathway = {
      status: 'not_verifiable_yet',
      reason: 'tier1',
      detail:
        'The pathway-classification input (inputs[1]) is RLS-restricted; the signed block is ' +
        'signature-bound but was not independently recomputed. Re-run --tier 2 --supabase-token ' +
        'to reproduce the (r_strategy, loop_type) breakdown from raw transactions.',
    };
    return null;
  }
  if (!a.pathwayCsvUrl) {
    context.pathway = {
      status: 'not_verifiable_yet',
      reason: 'no_pathway_url',
      detail:
        'Endpoint did not advertise pathway_csv_url; cannot fetch inputs[1] to recompute the ' +
        'pathway breakdown. The signed block is signature-bound.',
    };
    return null;
  }

  let pathwayCsv: string;
  try {
    pathwayCsv = await fetchPathwayCsv(a.pathwayCsvUrl, a.supabaseToken, a.fetcher);
  } catch (e) {
    context.pathway = {
      status: 'not_verifiable_yet',
      reason: 'fetch_failed',
      detail:
        `Could not fetch the pathway-classification CSV: ${e instanceof Error ? e.message : String(e)}. ` +
        `The signed block is signature-bound but was not independently recomputed.`,
    };
    return null;
  }

  // Bind the recompute input: SHA-256 of inputs[1] CSV must equal inputs[1].hash.
  if (!a.pathwayInput?.hash) {
    context.pathway = {
      status: 'not_verifiable_yet',
      reason: 'no_input_hash',
      detail:
        'Manifest has no inputs[1].hash to bind the pathway-classification CSV against; cannot ' +
        'trust a recompute from an unbound input. The signed block is signature-bound.',
    };
    return null;
  }
  const pathwayHash = await sha256Hex(pathwayCsv);
  if (pathwayHash !== a.pathwayInput.hash) {
    const detail =
      'SHA-256 of the pathway-classification CSV does not match manifest.inputs[1].hash — the ' +
      'recompute input does not bind to what was signed.';
    checks.push({
      name: 'pathway_input_hash',
      passed: false,
      tier: 2,
      expected: a.pathwayInput.hash,
      actual: pathwayHash,
      detail,
    });
    context.pathway = { status: 'mismatch', detail };
    return {
      kind: 'mismatch',
      failed_at: 'pathway_input_hash',
      detail,
      tier_run: a.tier,
      context,
    };
  }
  checks.push({
    name: 'pathway_input_hash',
    passed: true,
    tier: 2,
    expected: a.pathwayInput.hash,
    actual: pathwayHash,
  });

  // Recompute the composite block from the bound rows and compare to the signed
  // binding (AC1). R11 must split into closed_loop + open_loop_downcycle.
  const pathwayRows = parseCsv(pathwayCsv, {
    columns: true,
    skip_empty_lines: true,
    cast: false,
  }) as Array<Record<string, unknown>>;
  const recomputed = recomputePathwayOutputs(pathwayRows);
  const blockCmp = comparePathwayBlock(recomputed, pathwayBlock);
  if (!blockCmp.ok) {
    checks.push({ name: 'pathway_recomputation', passed: false, tolerance_dp: 4, detail: blockCmp.detail });
    context.pathway = { status: 'mismatch', detail: blockCmp.detail };
    return {
      kind: 'mismatch',
      failed_at: 'pathway_recomputation',
      detail: blockCmp.detail,
      tier_run: a.tier,
      context,
    };
  }

  // Assert the L2 outcomes_by_r_strategy projection equals the block at 4dp
  // (D2 = A / AC3). Absent (pre-P5b coarse form or no projection) → not a
  // failure; the authoritative block was still recomputed.
  const proj = compareL2Projection(a.publishedMetrics?.outcomes_by_r_strategy, pathwayBlock);
  if (proj.status === 'mismatch') {
    checks.push({ name: 'pathway_recomputation', passed: false, tolerance_dp: 4, detail: proj.detail });
    context.pathway = { status: 'mismatch', detail: proj.detail };
    return {
      kind: 'mismatch',
      failed_at: 'pathway_recomputation',
      detail: proj.detail,
      tier_run: a.tier,
      context,
    };
  }

  checks.push({ name: 'pathway_recomputation', passed: true, tolerance_dp: 4 });
  context.pathway = {
    status: 'verified',
    projection_checked: proj.status === 'match',
    detail:
      proj.status === 'match'
        ? 'Pathway breakdown recomputed from inputs[1] and matched the signed block; L2 projection asserted equal at 4dp.'
        : 'Pathway breakdown recomputed from inputs[1] and matched the signed block. No composite L2 projection present to cross-check (pre-P5b).',
  };
  return null;
}
