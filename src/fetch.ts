// src/fetch.ts
//
// HTTP fetchers. Pure `fetch()` against REST + Storage URLs. No Supabase SDK.
//
// Endpoint contract (spec §6.4):
//   GET {endpoint}/api/programme/:id/metrics[?published_version=N]
//   → 200 { programme_id, published_version, metrics, computation_manifest,
//           manifest_archive_url?, tier1_csv_url?, tier2_csv_url? }
//
// The three URL hints (`manifest_archive_url`, `tier1_csv_url`, `tier2_csv_url`)
// are forward-compatible additions: a server that omits them is still usable —
// the CLI falls back to the JSONB `computation_manifest` value and asks the
// user to supply explicit storage URLs via flags. When the hints are present,
// the CLI prefers the archive over the JSONB (spec AC7).
//
// Storage URL shapes (spec §4.2):
//   Tier 1 (anon-readable): {supabaseUrl}/storage/v1/object/public/computation-exports/{path}
//   Tier 2 (RLS-restricted): {supabaseUrl}/storage/v1/object/computation-exports/{path}
//                            + Authorization: Bearer {token}
//
// The manifest archive (`manifest_v{n}.json`) is always public; Tier 1 CSVs
// (`t1_v{n}.csv`) are public; Tier 2 CSVs (`t2_v{n}.csv`) are RLS-restricted.

import type { ComputationManifest, ES256JWK } from './crypto.js';

// =============================================================================
// Types
// =============================================================================

export interface ProgrammeMetricsResponse {
  programme_id: string;
  published_version: number;
  metrics: Record<string, unknown>;
  computation_manifest: ComputationManifest | null;
  // Forward-compatible URL hints. Present when the server has been updated.
  manifest_archive_url?: string;
  tier1_csv_url?: string;
  tier2_csv_url?: string;
}

export interface JWKKeyset {
  keys: ES256JWK[];
}

/** What the fetchers return to the orchestrator. */
export interface FetchedManifest {
  manifest: ComputationManifest;
  /** Where the manifest body came from — informational, surfaced in --verbose. */
  source: 'archive' | 'rest_jsonb';
  /** Resolved storage URL hints, if the endpoint provided them. */
  tier1CsvUrl?: string;
  tier2CsvUrl?: string;
}

/**
 * Distinct error class so the orchestrator can map specific failure modes to
 * VerifyResult states without leaking generic Errors into the report.
 */
export class FetchError extends Error {
  constructor(
    public readonly kind:
      | 'manifest_absent'
      | 'manifest_key_pending'
      | 'jwk_not_found'
      | 'jwk_key_id_missing'
      | 'tier1_not_found'
      | 'tier2_not_found'
      | 'tier2_unauthorized'
      | 'transport',
    message: string,
  ) {
    super(message);
    this.name = 'FetchError';
  }
}

// =============================================================================
// Public fetchers
// =============================================================================

/**
 * Fetch the programme metrics + manifest from the REST endpoint. When the
 * server provides a `manifest_archive_url` hint, re-fetch the archive and
 * prefer its bytes over the JSONB value (spec AC7).
 *
 * Returns FetchError('manifest_absent') when there is no manifest at all.
 * Returns FetchError('manifest_key_pending') when the signature is empty.
 */
export async function fetchProgrammeManifest(
  endpoint: string,
  programmeId: string,
  publishedVersion: number | undefined,
  fetcher: typeof fetch = fetch,
): Promise<FetchedManifest> {
  const restUrl = buildMetricsUrl(endpoint, programmeId, publishedVersion);
  let resp: Response;
  try {
    resp = await fetcher(restUrl, { headers: { accept: 'application/json' } });
  } catch (e) {
    throw new FetchError('transport', `Failed to reach ${restUrl}: ${(e as Error).message}`);
  }
  if (resp.status === 404) {
    throw new FetchError('manifest_absent', `No programme metrics at ${restUrl}`);
  }
  if (!resp.ok) {
    throw new FetchError('transport', `REST ${restUrl} returned ${resp.status}`);
  }
  const body = (await resp.json()) as ProgrammeMetricsResponse;

  if (!body.computation_manifest) {
    throw new FetchError('manifest_absent', 'Programme exists but has no computation_manifest');
  }
  if (body.computation_manifest.signature?.value === '') {
    // H5.02 key-pending state — manifest body written but unsigned. Treat as
    // not_verifiable_yet with a distinct sub-state.
    throw new FetchError(
      'manifest_key_pending',
      'Manifest exists but signature is empty (signing key not yet provisioned in this environment)',
    );
  }

  // Prefer archive bytes over JSONB when the endpoint advertises one.
  if (body.manifest_archive_url) {
    try {
      const archiveResp = await fetcher(body.manifest_archive_url, {
        headers: { accept: 'application/json' },
      });
      if (archiveResp.ok) {
        const archiveBody = (await archiveResp.json()) as ComputationManifest;
        return {
          manifest: archiveBody,
          source: 'archive',
          tier1CsvUrl: body.tier1_csv_url,
          tier2CsvUrl: body.tier2_csv_url,
        };
      }
      // 404 on archive but JSONB present is unusual — proceed with JSONB.
    } catch {
      // Transport error on archive — fall through to JSONB.
    }
  }

  return {
    manifest: body.computation_manifest,
    source: 'rest_jsonb',
    tier1CsvUrl: body.tier1_csv_url,
    tier2CsvUrl: body.tier2_csv_url,
  };
}

/**
 * Fetch the JWK keyset from the URL advertised by `manifest.signature.public_key_url`.
 * Returns the specific key matching `public_key_id`.
 *
 * Distinguishes between the keyset not existing (caller's --endpoint may be
 * the wrong environment) and the keyset existing but missing the key id.
 */
export async function fetchJwk(
  publicKeyUrl: string,
  publicKeyId: string,
  fetcher: typeof fetch = fetch,
): Promise<ES256JWK> {
  let resp: Response;
  try {
    resp = await fetcher(publicKeyUrl, { headers: { accept: 'application/json' } });
  } catch (e) {
    throw new FetchError(
      'transport',
      `Failed to reach signature.public_key_url (${publicKeyUrl}): ${(e as Error).message}`,
    );
  }
  if (resp.status === 404) {
    throw new FetchError(
      'jwk_not_found',
      `Key set not found at ${publicKeyUrl} — possible wrong-environment endpoint?`,
    );
  }
  if (!resp.ok) {
    throw new FetchError('transport', `JWK ${publicKeyUrl} returned ${resp.status}`);
  }
  const keyset = (await resp.json()) as JWKKeyset;
  const key = keyset.keys?.find((k) => k.kid === publicKeyId);
  if (!key) {
    throw new FetchError(
      'jwk_key_id_missing',
      `Key id "${publicKeyId}" absent from key set at ${publicKeyUrl}`,
    );
  }
  return key;
}

/**
 * Fetch a Tier 1 CSV. Public — no auth. Returns the raw CSV text.
 */
export async function fetchTier1Csv(
  url: string,
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const resp = await fetcher(url, { headers: { accept: 'text/csv' } });
  if (resp.status === 404) {
    throw new FetchError('tier1_not_found', `Tier 1 CSV not found at ${url}`);
  }
  if (!resp.ok) {
    throw new FetchError('transport', `Tier 1 ${url} returned ${resp.status}`);
  }
  return await resp.text();
}

/**
 * Fetch a Tier 2 CSV with a programme-participant Supabase JWT. RLS-restricted.
 * Returns the raw CSV text.
 */
export async function fetchTier2Csv(
  url: string,
  supabaseToken: string,
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const resp = await fetcher(url, {
    headers: {
      accept: 'text/csv',
      authorization: `Bearer ${supabaseToken}`,
    },
  });
  if (resp.status === 401 || resp.status === 403) {
    throw new FetchError(
      'tier2_unauthorized',
      `Tier 2 ${url} returned ${resp.status} — token does not have programme-participant access`,
    );
  }
  if (resp.status === 404) {
    throw new FetchError('tier2_not_found', `Tier 2 CSV not found at ${url}`);
  }
  if (!resp.ok) {
    throw new FetchError('transport', `Tier 2 ${url} returned ${resp.status}`);
  }
  return await resp.text();
}

// =============================================================================
// URL construction helpers (pure — testable without HTTP)
// =============================================================================

/** REST URL for /api/programme/:id/metrics with optional published_version. */
export function buildMetricsUrl(
  endpoint: string,
  programmeId: string,
  publishedVersion: number | undefined,
): string {
  const base = endpoint.replace(/\/$/, '');
  const versionQuery = publishedVersion !== undefined ? `?published_version=${publishedVersion}` : '';
  return `${base}/api/programme/${encodeURIComponent(programmeId)}/metrics${versionQuery}`;
}

/**
 * Tier 1 / archive storage URL (anon-readable). Used as a fallback when the
 * server does not advertise `tier1_csv_url` directly.
 */
export function buildPublicStorageUrl(
  supabaseUrl: string,
  programmeId: string,
  filename: string,
): string {
  const base = supabaseUrl.replace(/\/$/, '');
  return `${base}/storage/v1/object/public/computation-exports/${encodeURIComponent(programmeId)}/${filename}`;
}

/**
 * Tier 2 storage URL (RLS-restricted — note the missing `/public` segment per
 * spec §4.2). Used as a fallback when the server does not advertise
 * `tier2_csv_url` directly.
 */
export function buildPrivateStorageUrl(
  supabaseUrl: string,
  programmeId: string,
  filename: string,
): string {
  const base = supabaseUrl.replace(/\/$/, '');
  return `${base}/storage/v1/object/computation-exports/${encodeURIComponent(programmeId)}/${filename}`;
}
