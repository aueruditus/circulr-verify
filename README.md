# @circulr/verify

Independent verifier for `au.com.auspost.sustainability` §7 Computation Manifests. CLI counterpart to the `verify_computation` MCP tool published by `circulr-mcp-passport`.

Anyone can run this tool against a CirculR-published programme to check that:

- the manifest signature is valid against the platform's published key,
- the dataset hashes match the actual exported CSV data,
- the published aggregate metrics can be reproduced from those data.

No CirculR account required for the default check.

## Two Levels of Verification

The verifier reports one of two named claims, in the standard's terminology. Capitalisation matters — these are protocol terms, not descriptive prose.

### Aggregation Integrity

Default claim. Verifiable anonymously via the Tier 1 export.

Proves that the published aggregate equals the sum of published per-row values, and that the manifest signature is valid. Does **not** prove that the per-row values were correctly derived from raw inputs — Tier 1 is a projection of metric-driving columns, not a sufficient input set.

```
npx @circulr/verify --programme-id <uuid>
```

### Input Integrity

Stronger claim. Verifiable by programme participants via the Tier 2 export.

Proves that per-row values were correctly derived from underlying inputs by applying the canonical transform, in addition to all of Aggregation Integrity. Requires a programme-participant Supabase JWT because Tier 2 carries the raw input columns (e.g. `quantity_kg`, `emission_factor_value`) that Tier 1 omits.

```
npx @circulr/verify --programme-id <uuid> --tier 2 --supabase-token $TOKEN
```

A Tier 1 verifier always reports Aggregation Integrity, even when the manifest declares the stronger claim. A Tier 2 verifier reports Input Integrity only if the recompute succeeded against the raw inputs.

## Usage

### Install

```
npm install -g @circulr/verify
# or use npx without installing
npx @circulr/verify --programme-id <uuid>
```

### Command line

```
circulr-verify --programme-id <uuid>
               [--endpoint <url>]              # defaults to https://circulrdesigner.circulr.ai
               [--tier {1|2}]                  # default 1
               [--supabase-token <jwt>]        # required for --tier 2
               [--format {human|json}]         # default human
               [--verbose]                     # prints canonical body, hashes, JWK, independence check
               [--version <n>]                 # specific published_version; defaults to latest
```

Passing `--supabase-token` without `--tier 2` is treated as intent to verify at Tier 2; the verifier emits an info line and proceeds at Tier 2.

### Exit codes

| Code | Outcome |
|---|---|
| 0 | `VERIFIED` |
| 1 | `MISMATCH` |
| 2 | `NOT_VERIFIABLE_YET` |
| 3 | `ARCHIVE_LOCKED` (informational; CLI rarely surfaces this — present for parity with the MCP tool) |
| 64 | Usage error (sysexits) |

### JSON output

`--format json` produces machine-parseable output with a stable schema. Mismatches add a `failed_at` and `detail` field; not-yet-verifiable manifests add a `manifest_state` field (`"absent"` or `"key_pending"`).

```json
{
  "result": "verified",
  "claim": "aggregation_integrity",
  "stronger_claim_available": true,
  "stronger_claim_command": "npx @circulr/verify --programme-id <uuid> --tier 2 --supabase-token $TOKEN",
  "programme_id": "<uuid>",
  "published_version": 3,
  "manifest_version": "1.0",
  "computed_at": "2026-05-04T08:42:11Z",
  "metrics_source": "canonical_pipeline",
  "checks": [
    { "name": "manifest_signature", "passed": true, "algorithm": "ES256" },
    { "name": "tier1_input_hash", "passed": true },
    { "name": "metric_recomputation", "passed": true, "tolerance_dp": 4 }
  ],
  "manifest_claim_level": "aggregation_integrity",
  "independence_check": null
}
```

## What this verifies

Implements the Independent Reproduction Protocol from `au.com.auspost.sustainability` §7.4:

1. Fetch and verify manifest signature against the public key advertised by the manifest.
2. Fetch each input from `inputs[].dataset` and verify against `inputs[].hash`.
3. Fetch the transform function descriptor from `transform.function_url`.
4. Apply the declared version of the transform to the verified inputs.
5. Compare the recomputed output to the published `output.metrics_hash`.

Failure at any step is surfaced as `computation_unverifiable` with a specific sub-state so the caller learns *which* check failed.

## What this does not verify

- **Whether the published key is the right key.** Key trust is established out of band — the verifier reads `signature.public_key_url` from the manifest. If the manifest points at a malicious key URL serving a key under the same `public_key_id`, the verifier would accept it. Mitigate by pinning the expected key URL via your own tooling, or by running the verifier against multiple environments and comparing.
- **Whether the transform is correct in the abstract.** The verifier checks that a recompute under the declared transform reproduces the manifest's outputs. If the transform itself contains a bug, the verifier still reports VERIFIED — the manifest is internally consistent.
- **Whether Tier 1 is a sufficient set of inputs to justify the per-row values.** It is not — Tier 1 is a projection. To verify per-row derivation from raw inputs, run with `--tier 2`.
- **The per-pathway recovery breakdown.** Not yet bound by the manifest. The producer-side `SPEC_Pathways_Metric_Computation_Manifest` (inbound) will add a per-pathway binding under `manifest_v11` / `TRANSFORM_FUNCTION_VERSION 2.0.0`. Until that ships AND this verifier extends to cover it (a future release), per-pathway claims surface as `not_yet_verifiable`. The scalar metrics (`carbon_payback_ratio`, `net_carbon_impact_kg`, `transaction_count`, the `premium_pathway_rate` scalar) are bound and verifiable today.

## Architecture

```
src/
  index.ts        commander entry, arg parsing, format dispatch
  verify.ts       orchestration; returns the VerifyResult discriminated union
  fetch.ts        HTTP fetchers (manifest archive, REST fallback, JWK, Tier 1, Tier 2)
  crypto.ts       ES256 + SHA-256 + canonical JSON + base64url (lifted from CirculrDesignerGA)
  recompute.ts    per-source metric recompute (canonical_pipeline, enhanced_journeys, precomputed_sorting, designtime_estimation)
  report.ts       human + JSON formatters
tests/
  verify.test.ts  end-to-end scenarios
  crypto.test.ts  parity unit tests against the source's canonical JSON contract
  fixtures/       byte-stable fixtures generated by _generate.ts (round-trips through src/crypto.ts)
```

No `@supabase/*`. No `@noble/*`. Pure `fetch()` + Web Crypto.

## Status

**Stable (v1.0.0, `latest` on npm).** Verifies manifests under `TRANSFORM_FUNCTION_VERSION 1.0.0` and `3.x.x` (archived + embedded-projection shapes, anchored at CirculrDesignerGA commit `b3bfc026`). Tracks `au.com.auspost.sustainability` v0.4.2 §7. Production-proven — used to reproduce the §S6 RMW proof.

### What v1.0.0 includes

Since the alpha (`0.1.0-alpha.2`), the following have shipped:

- **Composite-pathway recompute** (#6) — per-pathway recovery breakdown recomputed from the `programme_pathways` table.
- **Live-JWKS wrapper** (#8) — accepts the platform's current `{ id, public_key_jwk }` verification-key shape.
- **Independent pathway verdict** (#9) — pathway claim reported independently of the scalar `metrics_hash` check (AC20 compliance).
- **Embedded-projection / `function_version` branching** (#10) — verifies `manifest_v3x` embedded-projection manifests in addition to `manifest_v10` archived manifests; branches on `TRANSFORM_FUNCTION_VERSION`.
- **3.1.0 metric-recomputation fidelity fixtures** (#11) — byte-stable canonical fixtures locking the round-then-sum recompute contract for `function_version 3.1.0`.

### Compatibility matrix

| Manifest version | Verifier coverage |
|---|---|
| `manifest_v10` and earlier (`function_version 1.0.0`) | Aggregation Integrity + Input Integrity (with `--tier 2`) |
| `manifest_v3x` (`function_version 3.x.x`, embedded-projection) | Aggregation Integrity + Input Integrity (with `--tier 2`) |
| `function_version 4.0.0` (reuse-basis columns bound into the canonical_pipeline Tier-2 projection) | Aggregation Integrity + Input Integrity. The 3 reuse-basis columns hash-verify via the manifest's `inputs[0].columns`; scalar recompute unchanged from 3.x. |
| `function_version 4.1.0` (displacement net-sign) | Aggregation Integrity + Input Integrity. The canonical_pipeline scalar recompute **credits `co2e_type='displacement'` as an avoided benefit** (matching the producer's §Fork-3 change). Version-gated on `function_version >= 4`. |
| `function_version 5.0.0` (quantity_units bound) | Aggregation Integrity + Input Integrity, **including reuse**: with `quantity_units` bound into Tier-2, the verifier independently re-derives each displacement row's co2e (`quantity_units × displacement_rate_applied × emission_factor_value`) and asserts it matches the published `co2e_kg` (`reuse_basis_recomputation`). Gated on `function_version >= 5` + `quantity_units` present. |
| `manifest_v11` (`function_version 2.0.0`, transactions-only, per inbound producer pathways spec) | Scalar metrics: covered by this verifier. Per-pathway recovery breakdown: extension lands in a future major (2.0.0). Until that ships, per-pathway claims surface as `not_yet_verifiable`. |

**Displacement net-sign convention (version-gated, archival-faithful):** for `function_version < 4` the canonical_pipeline net treats `co2e_type='displacement'` as a burden (the convention those manifests were signed under); for `function_version >= 4.1.0` it credits displacement as an avoided benefit. Archived pre-4.1.0 manifests therefore keep verifying under their own signed convention — the gate never retroactively flips their net.

### Versioning

1.1.0 added the `function_version 4.x` displacement net-sign gate (SPEC §Fork-3): the canonical_pipeline scalar recompute credits displacement as a benefit for 4.1.0+ manifests, version-gated so archived manifests stay reproducible.

2.0.0 adds **Reuse Input Integrity**: for `function_version >= 5` manifests carrying `quantity_units`, the verifier independently re-derives each displacement row's co2e (`quantity_units × displacement_rate_applied × emission_factor_value`) from the signed Tier-2 input and asserts it matches the published `co2e_kg` (the `reuse_basis_recomputation` check). This lifts reuse programmes from Aggregation Integrity (the sum trusts per-row co2e) to Input Integrity (per-row co2e re-derived from physical inputs). A tampered co2e that doesn't match its inputs fails `reuse_basis_recomputation`. Material / pre-5.0.0 manifests are unaffected (no reuse check — not applicable). The version string is the maturity signal.

## License

MIT.
