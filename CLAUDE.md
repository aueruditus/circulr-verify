# Claude Code Project Memory — circulr-verify

This repository is the **open-source verifier** half of the CirculR trust architecture (see [`05_Repository_Constellation`](../../../ObsidianVaults/CirculrTech/DesignerMode%20(TBI)/methodology/05_Repository_Constellation.md) §2.6). It exists at arm's length from the platform-build it verifies (`aueruditus/CirculrDesignerGA`) so that anyone — including parties who do not trust CirculR Tech to perform verification on their behalf — can audit a published claim end-to-end.

## What this repo is

`circulr-verify` ships the `@circulr/verify` npm package. The package is a CLI that implements the Independent Reproduction Protocol named in `au.com.auspost.sustainability` §7.4. Its MCP-tool counterpart (`verify_computation`) lives in `aueruditus/circulr-mcp-passport`; both surfaces implement the same protocol.

## Sibling repos

- **`aueruditus/CirculrDesignerGA`** — source of the canonical-JSON + ES256 + rounding contract this verifier mirrors. `src/crypto.ts` is a deliberate line-for-line lift of primitives from `CirculrDesignerGA/supabase/functions/publish-to-passport/computationManifest.ts`; the file header cites the source commit SHA. Drift between the two = signature mismatch on real prod manifests.
- **`aueruditus/circulr-mcp-passport`** — MCP-tool counterpart on the verifier side; consumer of the same manifest contract.
- **`aueruditus/au-com-auspost-sustainability-standard`** — published standard the verifier conforms to. §7 (Computation Manifest), §7.4 (Independent Reproduction Protocol), §9 (Conformance).

## Git workflow

Inherits the constellation's PR-only model:

- Direct commits to `main` or `test` are prohibited. Branch protection enforces this.
- Branch from `dev` for feature work; from `test` for promotion; from `main` only for hotfixes with explicit operator approval.
- Conventional commit prefixes: `feat:`, `fix:`, `chore:`, `ci:`, `docs:`, `refactor:`, `test:`.
- PR body template: Summary / Change scope / Test evidence / Rollback plan / Related issues.
- Merge with auto-merge so the gate is CI, not manual timing: `gh pr merge --auto --squash` (linear history on `main` and `test`).
- Promotion: `dev → test` direct merge OK; `test → main` always via PR (per `[[feedback_prod_promotion_via_pr]]` memory rule).
- **All git operations** (commit, push, branch, PR) **go through the `devops` sub-agent** when invoked from Claude Code, per the inherited constellation rule.

## What this repo is NOT

- Not the trust registry. The producer-side server infrastructure that certification authorities operate to publish attestations lives in `aueruditus/circulr-trust-registry`. The verifier is the consumer-side library/CLI that anyone can run against those attestations.
- Not a Supabase project. The verifier holds no DB schema, no Edge Functions, no migrations. It is pure TypeScript that talks to public Supabase Storage URLs over `fetch()`.
- Not tied to CirculR's deployment chain. `circulr-migrations` is irrelevant here. The verifier ships to npm.

## Source files of interest in CirculrDesignerGA

When implementing or debugging, keep these open in a side buffer:

- `supabase/functions/publish-to-passport/computationManifest.ts` — canonical-JSON + ES256 + `roundHalfEven` contract. `src/crypto.ts` mirrors this.
- `supabase/functions/publish-to-passport/index.ts:362-467` (approx) — per-source compute paths the verifier's `recompute.ts` must mirror.
- `supabase/functions/publish-to-passport/dataExports.ts:75-113` — Tier 1 / Tier 2 column projections per source.
- `supabase/functions/publish-to-passport/computationManifest.test.ts` — fixture format and assertion patterns the test suite follows.
- `public/.well-known/verification-keys.{dev,test,prod}.json` — JWK URL shape consumed via `manifest.signature.public_key_url`.

## Determinism contract

Every byte of the manifest signature depends on byte-stable serialisation. The contract is documented in detail at the top of `CirculrDesignerGA/supabase/functions/publish-to-passport/computationManifest.ts`. Re-reading that file before touching `src/crypto.ts` is the cheapest way to avoid silently breaking signature verification.

## Spec source of truth

`SPEC_H5_03_04_09_Cross_Repo_Verifier_v0_3.md` (in the author's Obsidian vault at `CirculrTech/AgenticCommerce/specifications/SPEC_H5/`). Plan-only on `aueruditus/CirculrDesignerGA` (PR #143).
