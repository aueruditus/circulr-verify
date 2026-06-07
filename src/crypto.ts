// src/crypto.ts
//
// Determinism contract — DO NOT change without coordinating with the source.
//
// The primitives below (`roundHalfEven`, `canonicalJsonStringify`, `sha256Hex`,
// `base64UrlEncode`, `base64UrlDecode`) are lifted byte-for-byte from:
//
//   aueruditus/CirculrDesignerGA
//     supabase/functions/publish-to-passport/computationManifest.ts
//   source commit: b3bfc026 ("feat(mca): Phase 7c — manifest claim_level +
//                             attestation_reference + independence_check (#166)")
//
// The two files MUST stay byte-equivalent on these primitives. Drift = signature
// failures on real prod manifests. The fixture generator at
// `tests/fixtures/_generate.ts` round-trips through this module (NOT a parallel
// implementation) so the fixtures and the verifier cannot drift independently.
//
// `verifyES256` and `importEs256VerifyingKey` are the verifier-side counterparts
// to the source's `es256SignBase64Url` and `importEs256SigningKey`. They are
// the only members of this module without a direct source-line cousin.
//
// Run-time notes:
//   - Node ≥20 exposes Web Crypto as `globalThis.crypto`. No import needed.
//   - subtle.importKey('jwk', …) MUST pin `extractable: false` and
//     `usages: ['verify']` for browser portability (per spec §11.5).
//   - ES256 produces IEEE P1363 raw r||s (64 bytes for P-256). Web Crypto's
//     subtle.verify accepts the same format. Encoding is direct.
// =============================================================================

// Type-only import — the runtime dependency is one-way (pathway.ts imports
// roundHalfEven from here), so this carries no import cycle.
import type { PathwayOutput } from './pathway.js';

const ROUNDING_DECIMALS = 4;

/**
 * Banker's rounding (IEEE 754 round-half-to-even). JavaScript has no native
 * implementation; Math.round is half-away-from-zero which is NOT what we want
 * for canonical-JSON serialisation.
 *
 * Examples at 4dp: 0.12345 → 0.1234, 0.12355 → 0.1236, 0.12365 → 0.1236,
 * 0.12375 → 0.1238.
 */
export function roundHalfEven(value: number, decimals: number = ROUNDING_DECIMALS): number {
  if (!Number.isFinite(value)) return value;
  const factor = Math.pow(10, decimals);
  const scaled = value * factor;
  const floor = Math.floor(scaled);
  const diff = scaled - floor;
  const EPSILON = 1e-9;
  if (Math.abs(diff - 0.5) < EPSILON) {
    return (floor % 2 === 0 ? floor : floor + 1) / factor;
  }
  return Math.round(scaled) / factor;
}

/**
 * Canonical JSON: keys sorted alphabetically (recursive), numeric values passed
 * through roundHalfEven(n, 4). No whitespace, no trailing newline.
 *
 * NOTE: numbers are stringified through `roundHalfEven` BEFORE serialisation
 * (per spec §11.6 — the rounding belongs inside this function, not on the
 * caller side). Any drift here = signature mismatch on real prod manifests.
 */
export function canonicalJsonStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return 'null';
    return roundHalfEven(value).toString();
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJsonStringify).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const pairs = keys.map((k) => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k]));
    return '{' + pairs.join(',') + '}';
  }
  return JSON.stringify(value);
}

/** SHA-256 hex digest of a UTF-8 string. */
export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** RFC 4648 §5 base64url encoding (no padding). */
export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** RFC 4648 §5 base64url decoding (accepts padded or unpadded input). */
export function base64UrlDecode(s: string): Uint8Array {
  const stripped = s.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (stripped.length % 4)) % 4;
  const padded = stripped + '='.repeat(padding);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// =============================================================================
// Verifier-side counterparts (no direct source-line cousin)
// =============================================================================

/**
 * JWK shape the verifier accepts. Mirrors what
 * CirculrDesignerGA/public/.well-known/verification-keys.{env}.json serves.
 */
export interface ES256JWK {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  kid?: string;
  use?: string;
  alg?: string;
  // Permissive — verification-keys files may add metadata fields.
  [k: string]: unknown;
}

/**
 * Import a P-256 public key from JWK form for ECDSA verification. Pins
 * `extractable: false` and `usages: ['verify']` for browser-build portability
 * (spec §11.5 / §11.10).
 */
export async function importEs256VerifyingKey(jwk: ES256JWK): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    'jwk',
    jwk as JsonWebKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

/**
 * Verify an ES256 base64url signature over a UTF-8 message against an imported
 * P-256 public key. Returns true iff the signature is valid.
 *
 * Counterpart to the source's `es256SignBase64Url`. Web Crypto's subtle.verify
 * expects raw IEEE P1363 r||s (64 bytes for P-256); we feed it the base64url-
 * decoded bytes directly.
 */
export async function verifyES256(
  canonicalMessage: string,
  signatureBase64Url: string,
  key: CryptoKey,
): Promise<boolean> {
  const sig = base64UrlDecode(signatureBase64Url);
  const msg = new TextEncoder().encode(canonicalMessage);
  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    sig as BufferSource,
    msg as BufferSource,
  );
}

// =============================================================================
// Manifest body type — mirrors the source's `ComputationManifest`.
// =============================================================================

export type ClaimLevel = 'aggregation_integrity' | 'input_integrity';

export type MetricsSource =
  | 'canonical_pipeline'
  | 'enhanced_journeys'
  | 'precomputed_sorting'
  | 'designtime_estimation';

export interface IndependencePair {
  left: 'measurement_platform' | 'attestor' | 'certifier';
  right: 'measurement_platform' | 'attestor' | 'certifier';
  shared_id: string;
}

export interface IndependenceCheck {
  measurement_platform_id: string;
  attestor_id: string;
  certifier_ids: string[];
  non_independent_pairs: IndependencePair[];
  determined_level: ClaimLevel;
  determined_at: string;
}

export interface AttestationReference {
  registry_url: string | null;
  aggregate_record_id: string;
  manifest_hash_pinned: string | null;
}

export interface DatasetHash {
  dataset: string;
  row_count: number;
  hash: string;
  columns: string[];
  period_start: string | null;
  period_end: string | null;
  attestation_reference?: AttestationReference;
}

export interface OutputHash {
  metrics_hash: string;
  metrics_source: string;

  // BUILD_MetricsHash_Embedded_Projection_v0_1 (producer v3.0.0) — the canonical
  // metrics projection that metrics_hash binds, EMBEDDED in the signed output so
  // the manifest is a self-contained Merkle leaf carrying its own preimage:
  //   metrics_hash = SHA-256(canonicalJsonStringify(metrics)).
  // Optional in the TYPE so archived 1.0.0/2.0.0 manifests — whose metrics_hash
  // was the whole programme_metrics row, with no embedded projection — stay legal
  // (mirrors pathway_outputs? below). Present iff function_version >= 3.0.0.
  metrics?: Record<string, unknown>;

  // SPEC_Pathways_Metric_Computation_Manifest §5.4 (P5a) — the authoritative,
  // signed per-(r_strategy, loop_type) recovery breakdown. Carried INSIDE the
  // signed `output` block, so it is bound by the manifest signature. Optional in
  // the TYPE so archived function_version 1.0.0 manifests (which predate the
  // block) stay legal — mirrors claim_level? / independence_check? optionality.
  // The v2.0.0 producer ALWAYS populates it (possibly []). Co-design D2 = A: this
  // block is authoritative; the L2 outcomes_by_r_strategy is a checked projection.
  pathway_outputs?: PathwayOutput[];
}

export interface TransformReference {
  function_id: string;
  function_version: string;
  function_url: string;
  description: string;
}

export interface ComputationMeta {
  transform: TransformReference;
  emission_factors_hash: string;
  rounding_rule: 'ROUND_HALF_EVEN_4DP';
  null_handling: 'null_as_zero';
}

export interface ManifestSignature {
  algorithm: 'ES256';
  public_key_id: string;
  public_key_url: string;
  value: string;
}

export interface ComputationManifest {
  version: '1.0';
  programme_id: string;
  canvas_id: string;
  published_version: number;
  computed_at: string;
  inputs: DatasetHash[];
  output: OutputHash;
  computation: ComputationMeta;
  claim_level?: ClaimLevel;
  independence_check?: IndependenceCheck;
  signature: ManifestSignature;
}

/**
 * Strip the `signature` envelope to reconstruct the canonical signing body.
 * The source signs the body BEFORE attaching the signature — see
 * computationManifest.ts `generateComputationManifest` step 7+8.
 */
export function manifestSigningBody(m: ComputationManifest): string {
  // Type predicate: every property except `signature` belongs to the body.
  const { signature: _sig, ...body } = m;
  return canonicalJsonStringify(body);
}
