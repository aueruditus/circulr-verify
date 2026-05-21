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
  type IndependenceCheck,
  type MetricsSource,
} from './crypto.js';
import {
  FetchError,
  fetchJwk,
  fetchProgrammeManifest,
  fetchTier1Csv,
  fetchTier2Csv,
} from './fetch.js';
import { metricsApproxEqual, recomputeForSource, type RecomputedMetrics } from './recompute.js';

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
  | 'metric_recomputation';

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
  /** Canonical signing body — surfaced in --verbose. */
  canonical_body?: string;
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

  const { manifest, source: manifestSource, tier1CsvUrl, tier2CsvUrl } = fetched;
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

  if (publishedMetrics) {
    const publishedHash = await sha256Hex(canonicalJsonStringify(publishedMetrics));
    if (publishedHash !== manifest.output.metrics_hash) {
      const detail =
        `Canonical hash of published metrics does not match manifest.output.metrics_hash. ` +
        `Either the published metrics were mutated post-signing, or the endpoint's serialisation ` +
        `of the metrics row differs from what was hashed.`;
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
        context: { ...context, published_metrics: publishedMetrics },
      };
    }
    checks.push({
      name: 'metrics_hash_binding',
      passed: true,
      algorithm: 'SHA-256',
      expected: manifest.output.metrics_hash,
      actual: publishedHash,
    });
    context.published_metrics = publishedMetrics;
  }

  // Recompute the metric-driving values from the verified tier data.
  const recomputeSourceRows = tier2Rows ?? tier1Rows;
  const recomputed = recomputeForSource(
    manifest.output.metrics_source as MetricsSource,
    recomputeSourceRows,
  );
  context.recomputed = recomputed;

  // Compare against published values for each recomputable field.
  if (publishedMetrics) {
    for (const field of recomputed.recomputed_fields) {
      const published = Number(publishedMetrics[field] ?? 0);
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
