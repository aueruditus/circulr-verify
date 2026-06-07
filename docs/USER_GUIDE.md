# `@circulr/verify` — Installation & User Guide

| Field | Value |
|---|---|
| **Tool** | `@circulr/verify` (CLI) |
| **Version** | 1.0.0 |
| **Status** | Stable (`latest` on npm) — see [§14 Status & roadmap](#14-status--roadmap) |
| **Spec** | `au.com.auspost.sustainability` v0.4.2 §7 (Computation Manifest), §7.4 (Independent Reproduction Protocol) |
| **Source** | https://github.com/aueruditus/circulr-verify |
| **License** | MIT |

---

## Contents

1. [What this tool does](#1-what-this-tool-does)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Quick start](#4-quick-start)
5. [Two levels of verification](#5-two-levels-of-verification)
6. [Command reference](#6-command-reference)
7. [Output formats](#7-output-formats)
8. [Exit codes](#8-exit-codes)
9. [Worked examples](#9-worked-examples)
10. [Verbose mode](#10-verbose-mode)
11. [CI integration](#11-ci-integration)
12. [Troubleshooting](#12-troubleshooting)
13. [What the verifier checks (and what it doesn't)](#13-what-the-verifier-checks-and-what-it-doesnt)
14. [Status & roadmap](#14-status--roadmap)
15. [Reporting issues](#15-reporting-issues)

---

## 1. What this tool does

`circulr-verify` lets anyone independently check a sustainability claim published by a CirculR-powered programme. It implements the **Independent Reproduction Protocol** named in `au.com.auspost.sustainability` §7.4:

1. Fetches the programme's signed **computation manifest** from the platform's public endpoint.
2. Verifies the ES256 signature against the platform's published public key.
3. Verifies that the published metrics are correctly bound by the manifest's `metrics_hash`.
4. Recomputes the metric values from the published input data (Tier 1 anon-readable, or Tier 2 if you have programme-participant access) and confirms they match.
5. (Tier 2 only) Verifies that the raw input CSV hashes to the value bound by the manifest.

Result is one of four discriminated outcomes: `VERIFIED`, `MISMATCH`, `NOT_VERIFIABLE_YET`, `ARCHIVE_LOCKED`.

You do **not** need a CirculR account or any credentials to run the default (Tier 1) check.

---

## 2. Prerequisites

- **Node.js ≥ 20** — the verifier uses Web Crypto (`crypto.subtle`) natively, which Node 20+ exposes as `globalThis.crypto`. Older Node versions are unsupported.
- **Network access** to:
  - the platform endpoint (default `https://circulrdesigner.circulr.ai`);
  - the platform's public key URL advertised inside each manifest;
  - the storage URLs for Tier 1 (public) and, if running Tier 2, Tier 2 (RLS-restricted).
- **A Supabase JWT** with programme-participant access **only if** you want to run at Tier 2. Tier 1 is anonymous.

Check Node version:

```bash
node --version
# v20.x or later required
```

---

## 3. Installation

### A. npm (recommended)

```bash
npm install -g @circulr/verify
circulr-verify --programme-id <uuid>
```

The binary resolves as `circulr-verify` on your `PATH`.

### B. `npx` (no install)

```bash
npx @circulr/verify --programme-id <uuid>
```

`npx` downloads the package on demand — no install step.

### C. Local clone (development / offline)

```bash
git clone git@github.com:aueruditus/circulr-verify.git
cd circulr-verify
npm install
npm run build
```

After this, the binary is at `dist/index.js`. Invoke with `node dist/index.js …`.

To run the test suite:

```bash
npm test
```

---

## 4. Quick start

The simplest end-to-end run:

```bash
npx @circulr/verify --programme-id <uuid>
```

Default behaviour:

- Fetches the latest published version of the programme's manifest from `https://circulrdesigner.circulr.ai/api/programme/<uuid>/metrics`.
- Runs the Aggregation Integrity check (Tier 1, no credentials).
- Prints a human-readable report and exits with code `0` on success.

For machine-parseable output:

```bash
npx @circulr/verify --programme-id <uuid> --format json
```

For the stronger Input Integrity check (programme-participant access required):

```bash
npx @circulr/verify --programme-id <uuid> --tier 2 --supabase-token $TOKEN
```

If running from a local clone (`node dist/index.js`), the arguments are identical.

---

## 5. Two levels of verification

Capitalisation matters — these are protocol terms.

### Aggregation Integrity (default — anonymous)

**Verifiable by anyone** using the public Tier 1 export.

Proves that:

- the manifest signature is valid against the platform's published key;
- the published per-row aggregates are internally consistent with what was signed;
- the published metrics can be reproduced from the Tier 1 input projection.

**Does NOT prove** that per-row values themselves were correctly derived from raw inputs — Tier 1 is a projection of metric-driving columns, not a sufficient input set. For example, on the `canonical_pipeline` source, Tier 1 carries pre-computed `co2e_kg` per row but not the underlying `quantity_kg × emission_factor_value` that produced it.

Default exit-0 outcome.

### Input Integrity (Tier 2 — programme participants)

**Verifiable by programme participants** holding a Supabase JWT with programme-participant access.

Proves everything Aggregation Integrity proves, **plus**:

- the raw input CSV bytes (Tier 2 column projection) hash to the value bound by the manifest;
- the per-row values were correctly derived from the underlying inputs by applying the canonical transform.

Requires `--tier 2 --supabase-token <jwt>`.

### Reading the verifier's claim line

The verifier reports the claim **it actually established**, not the claim the manifest declares.

| Verifier ran | Manifest declares | Verifier reports |
|---|---|---|
| Tier 1 | (absent / aggregation_integrity) | Aggregation Integrity |
| Tier 1 | input_integrity | Aggregation Integrity (with a "manifest declares stronger" note) |
| Tier 2 (recompute matched) | aggregation_integrity | Input Integrity |
| Tier 2 (recompute matched) | input_integrity | Input Integrity |

A Tier 1 verifier never reports Input Integrity even if the manifest claims it.

---

## 6. Command reference

```
circulr-verify --programme-id <uuid>
               [--endpoint <url>]
               [--tier {1|2}]
               [--supabase-token <jwt>]
               [--format {human|json}]
               [--verbose]
               [--version <n>]
               [-h | --help]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--programme-id` | UUID | — (required) | Programme identifier to verify. |
| `--endpoint` | URL | `https://circulrdesigner.circulr.ai` | Application URL of the verifying platform. Override for non-production environments. |
| `--tier` | `1` or `2` | `1` | Verification tier. Tier 1 = Aggregation Integrity (anonymous); Tier 2 = Input Integrity (requires token). |
| `--supabase-token` | JWT string | — | Programme-participant Supabase JWT. **Required for `--tier 2`.** Supplying this flag without `--tier 2` implies Tier 2 (the verifier emits an info line and proceeds at Tier 2). |
| `--format` | `human` or `json` | `human` | Output format. JSON is schema-stable and suitable for CI consumption. |
| `--verbose` | flag | off | Print canonical body, intermediate hashes, JWK, and the independence-check block (when the manifest carries it). |
| `--version` | integer ≥ 1 | (latest) | Verify a specific `published_version` of the programme. If omitted, verifies the latest. |
| `--help`, `-h` | flag | — | Print usage. |

Invalid combinations:

- `--tier 2` without `--supabase-token` → usage error (exit `64`).
- `--format` other than `human` / `json` → usage error.
- `--version` not a positive integer → usage error.

---

## 7. Output formats

### Human (default)

```
✓ AGGREGATION INTEGRITY VERIFIED

Programme:        prog-uuid-1
Published vers.:  3
Manifest version: 1.0
Computed at:      2026-05-04T08:42:11.000Z
Public key:       circulr-platform-prod-2026-04 @ https://circulrdesigner.circulr.ai/.well-known/verification-keys.json
Metrics source:   canonical_pipeline
Manifest source:  archive

Checks performed:
  ✓ manifest signature (ES256)
  ✓ metrics hash binding (SHA-256)
  ✓ tier1 input aggregate (tier=1)
  ✓ metric recomputation (4dp tolerance)

For Input Integrity verification, run with --tier 2 --supabase-token $TOKEN
(requires programme-participant access).
```

The footer ("For Input Integrity verification…") appears only on Tier 1 outcomes; Tier 2 verifiers suppress it.

### JSON (`--format json`)

```json
{
  "result": "verified",
  "claim": "aggregation_integrity",
  "tier_run": 1,
  "stronger_claim_available": true,
  "stronger_claim_command": "npx @circulr/verify --programme-id prog-uuid-1 --tier 2 --supabase-token $TOKEN",
  "programme_id": "prog-uuid-1",
  "published_version": 3,
  "manifest_version": "1.0",
  "computed_at": "2026-05-04T08:42:11.000Z",
  "metrics_source": "canonical_pipeline",
  "public_key": {
    "id": "circulr-platform-prod-2026-04",
    "url": "https://circulrdesigner.circulr.ai/.well-known/verification-keys.json"
  },
  "manifest_source": "archive",
  "checks": [
    { "name": "manifest_signature", "passed": true, "algorithm": "ES256" },
    { "name": "metrics_hash_binding", "passed": true, "algorithm": "SHA-256",
      "expected": "9e3a…", "actual": "9e3a…" },
    { "name": "metric_recomputation", "passed": true, "tolerance_dp": 4 }
  ],
  "manifest_claim_level": "aggregation_integrity",
  "independence_check": null
}
```

Schema notes:

- `claim` and `manifest_claim_level` can differ — the former reports what the verifier established, the latter what the manifest declares.
- `stronger_claim_available` is `true` only on Tier 1 verified outcomes; null otherwise.
- On `mismatch`, the object gains `failed_at` (the check that failed) and `detail`.
- On `not_verifiable_yet`, the object gains `manifest_state: "absent" | "key_pending"`.
- On `archive_locked`, the object gains `existing_function_version` and `requested_function_version`.

---

## 8. Exit codes

`circulr-verify` follows the `sysexits.h` convention.

| Code | Outcome | Meaning |
|---|---|---|
| `0` | `VERIFIED` | All checks passed. |
| `1` | `MISMATCH` | A check failed. Inspect `failed_at` (JSON) or the report. |
| `2` | `NOT_VERIFIABLE_YET` | The manifest is absent, or its signature is pending key provisioning (rollout window). |
| `3` | `ARCHIVE_LOCKED` | Informational only — the MCP-side counterpart returns this when a republish under a different `function_version` was refused. The CLI normally does not surface it. |
| `64` | Usage error | Bad flags or missing required arguments. |

Use these codes in CI gates:

```bash
npx @circulr/verify --programme-id "$PROG" --format json
case $? in
  0) echo "verified" ;;
  1) echo "mismatch — gate failed"; exit 1 ;;
  2) echo "not yet verifiable — soft-pass" ;;
  *) echo "unexpected"; exit 2 ;;
esac
```

---

## 9. Worked examples

### 9.1 Verify the latest version anonymously

```bash
node dist/index.js --programme-id 3f51a8f2-…-…
```

### 9.2 Verify a specific historical version

```bash
node dist/index.js --programme-id 3f51a8f2-…-… --version 3
```

The verifier reads the archived `manifest_v3.json` (immutable per spec AC7) rather than the live JSONB column.

### 9.3 Verify against a non-production environment

```bash
# DEV
node dist/index.js \
  --programme-id 3f51a8f2-…-… \
  --endpoint https://circulrdesigner.dev.circulr.tech

# TEST
node dist/index.js \
  --programme-id 3f51a8f2-…-… \
  --endpoint https://circulrdesigner.test.circulr.tech
```

If you point a DEV manifest at the PROD endpoint (or vice versa), the verifier returns `MISMATCH(manifest_signature)` with the hint *"key not found at advertised URL — possible wrong-environment endpoint?"*. This is intentional — per H5.02 environment isolation, each environment has its own keyset.

### 9.4 Verify Input Integrity as a programme participant

```bash
node dist/index.js \
  --programme-id 3f51a8f2-…-… \
  --tier 2 \
  --supabase-token "$SUPABASE_JWT"
```

Or simply (the verifier infers Tier 2 from the token):

```bash
node dist/index.js --programme-id 3f51a8f2-…-… --supabase-token "$SUPABASE_JWT"
# info: --supabase-token supplied; verifying at Tier 2 (Input Integrity).
```

How to get a Supabase JWT: sign in to the CirculR portal as a programme participant; the session token is your JWT. (A short-lived token-exchange endpoint is planned — spec Open Q4 — but bring-your-own-JWT is the v1 contract.)

### 9.5 Pipe JSON output into other tools

```bash
node dist/index.js --programme-id 3f51a8f2-…-… --format json \
  | jq '{result, claim, mismatch: .failed_at}'
```

Or compare against an expected outcome:

```bash
result=$(node dist/index.js --programme-id 3f51a8f2-…-… --format json | jq -r .result)
[ "$result" = "verified" ] || { echo "verification failed"; exit 1; }
```

---

## 10. Verbose mode

`--verbose` adds three blocks to the human output:

1. **Canonical signing body** — the exact UTF-8 bytes the ES256 signature was verified against. Useful when debugging signature mismatches across environments.
2. **Independence check** — the `(measurement_platform, attestor, certifier)` triple comparison, the `determined_level`, and any non-independent pairs. Present when the manifest carries an `independence_check` block (Phase 7c+).
3. **Recomputed metric values** — the per-source recompute outputs (`premium_pathway_rate`, `net_carbon_impact_kg`, `carbon_payback_ratio`) the verifier produced from Tier 1 / Tier 2 rows.

Example:

```
✓ AGGREGATION INTEGRITY VERIFIED
…
— verbose —
Independence check:
  determined_level: Input Integrity
  measurement_platform: org-circulr
  attestor:             org-circulr
  certifiers:           (none)
  non_independent_pairs:
    measurement_platform ↔ attestor  (shared_id=org-circulr)
Recomputed metric values:
  net_carbon_impact_kg: 6
  carbon_payback_ratio: 4
```

`--verbose` is informational only; it does not change verification behaviour.

---

## 11. CI integration

The verifier is designed to gate releases. A minimal GitHub Actions step:

```yaml
- name: Verify programme metrics
  run: |
    npx @circulr/verify \
      --programme-id ${{ vars.PROGRAMME_ID }} \
      --endpoint ${{ vars.CIRCULR_ENDPOINT }} \
      --format json > verify.json
    jq -e '.result == "verified"' verify.json
```

For programme-participant CI checks at Tier 2:

```yaml
- name: Verify Input Integrity
  run: |
    npx @circulr/verify \
      --programme-id ${{ vars.PROGRAMME_ID }} \
      --supabase-token ${{ secrets.SUPABASE_JWT }} \
      --format json > verify.json
    jq -e '.result == "verified" and .claim == "input_integrity"' verify.json
```

Treat `NOT_VERIFIABLE_YET` as a soft-pass during the H5.02 Phase 12 key rollout window in the relevant environment.

---

## 12. Troubleshooting

### `NOT_VERIFIABLE_YET` (manifest_state: absent)

The endpoint has no manifest for the programme. Either:

- the programme has never been published to the passport (no `programme_metrics` row);
- the programme was published before manifest signing was enabled in this environment;
- the `--programme-id` is wrong;
- the `--endpoint` points at the wrong environment.

Confirm with `--verbose` and inspect the endpoint hit.

### `NOT_VERIFIABLE_YET` (manifest_state: key_pending)

The manifest body exists but the signature is empty. This is the H5.02 rollout key-pending window — manifest bodies were written before the signing key was provisioned in that environment. Wait for Phase 12 keys to land, or verify against an environment where signing is live.

### `MISMATCH` (manifest_signature) — "key not found at advertised URL — possible wrong-environment endpoint?"

The manifest's `signature.public_key_url` returned 404, or the JWK keyset at that URL doesn't contain a key with the manifest's `signature.public_key_id`. Cross-check that `--endpoint` matches the environment that published the manifest.

### `MISMATCH` (manifest_signature) — generic

The ES256 verification of the canonical body failed. The manifest may have been tampered with, or there is a canonical-JSON drift between the producer and this verifier. Run with `--verbose` and compare the printed canonical body against the manifest archive byte-for-byte.

### `MISMATCH` (metric_recomputation) at Tier 1

Most often expected: Tier 1 is a projection that omits raw inputs. For some sources (`enhanced_journeys` especially) the per-row metric values may have been derived from `metrics.net_carbon_impact_kg` (Tier 2 only) rather than the `co2e` fallback. Re-run with `--tier 2 --supabase-token` to confirm against the raw inputs.

If Tier 2 also mismatches, the published metrics genuinely cannot be reproduced from the verified inputs under the declared transform — surface the discrepancy to the platform operator.

### `MISMATCH` (tier2_input_hash)

The Tier 2 CSV bytes do not hash to `manifest.inputs[0].hash`. Either the Tier 2 export was mutated post-signing, or the manifest references a different input version than the CSV. Use `--version <n>` to verify against a specific snapshot.

### `MISMATCH` (tier1_input_aggregate) — "Endpoint did not advertise tier1_csv_url"

The endpoint REST response is in a backwards form that omits the storage URL hints. Until the REST wrapper in `circulr-mcp-passport` ships its Phase 7 update, run the verifier locally against a development endpoint that does advertise the hints.

### `Unexpected error: FetchError: Failed to reach …`

Transport-level failure. Check the endpoint URL, your network, and (for Tier 2) that the Supabase storage host is reachable.

### Tests fail with crypto / Web Crypto errors

Confirm Node version: `node --version` must be ≥ 20.

---

## 13. What the verifier checks (and what it doesn't)

### Checks

- **ES256 signature** over the manifest body using the public key advertised by `manifest.signature.public_key_url`.
- **Metrics hash binding** — that the published `metrics` row hashes (under the canonical-JSON contract) to `manifest.output.metrics_hash`. This proves "what was published is what was signed".
- **Per-source recompute** — that the published metric values are reproducible from the verified tier data under the declared transform.
- **Tier 2 input hash** (Tier 2 only) — that the Tier 2 CSV bytes hash to `manifest.inputs[0].hash`.

### What it does NOT check

- **Whether the published key is the right key.** Key trust is established out of band — the verifier reads `signature.public_key_url` from the manifest. If the manifest points at a malicious key URL serving a key under the same `public_key_id`, the verifier accepts it. Mitigate by:
  - pinning the expected key URL via your own tooling;
  - cross-checking multiple environments;
  - verifying the platform's published key fingerprint out of band.
- **Whether the transform itself is correct in the abstract.** The verifier confirms that *applying the declared transform* to the verified inputs reproduces the manifest's outputs. If the transform has a bug, the verifier still reports `VERIFIED` — the manifest is internally consistent.
- **Whether Tier 1 is a sufficient input set.** It isn't — Tier 1 is a projection. The Tier 1 verifier reports Aggregation Integrity precisely because the stronger Input Integrity claim requires Tier 2 access.
- **Off-chain attestations referenced by the manifest** (`independence_check`, `attestation_reference`). The verifier surfaces these in `--verbose` for the caller to inspect; it does not call out to attestor registries.

### Standards reference

`au.com.auspost.sustainability` v0.4.2 §7.4 — Independent Reproduction Protocol. v0.5.x Working Draft will add §7.4.1 Claim Levels and split §9 Conformance into "Aggregation Integrity MUST" and "Input Integrity SHOULD".

---

## 14. Status & roadmap

**v1.0.0 is the first stable release** (`latest` on npm, production-proven). The table below shows what has shipped and what is planned for future majors.

| Milestone | What lands | Status |
|---|---|---|
| CLI scaffolding + crypto + fetch + verify + recompute + formatters + tests | Phase 1 foundation | Done |
| Branch protection + CI gate | `test`/`main` protected | Done |
| `circulr-mcp-passport` REST surface + `verify_computation` MCP tool | URL-hint endpoint | Done |
| Live-JWKS wrapper + independent pathway verdict + embedded-projection branching | PRs #8, #9, #10 | Done |
| 3.1.0 fidelity fixtures | PR #11 | Done |
| **v1.0.0 stable release** (`latest`) | This release | Done |
| `manifest_v11` / `function_version 2.0.0` per-pathway recovery breakdown | v2.0.0 (future major) | Planned — gated on producer spec shipment |
| Standard v0.5.x amendment | Standards-process | Pending |

---

## 15. Reporting issues

- Bug reports / behaviour deviations: open an issue at https://github.com/aueruditus/circulr-verify/issues.
- Spec deviations or contract questions: cross-reference the relevant spec identifier in the issue body so the spec author can track required amendments.
- Security issues (manifest forgery vectors, signature-bypass classes): do **not** open a public issue — email the maintainer directly at ian.wong@eruditus.com.au.

The verifier accepts PRs against `dev`; the constellation's conventional-commit + linear-history + CI-gate workflow applies.

---

*Doc v2, 2026-06-07. Updated for v1.0.0 stable release.*
