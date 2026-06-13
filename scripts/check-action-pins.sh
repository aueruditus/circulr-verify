#!/usr/bin/env bash
# ============================================================================
# check-action-pins.sh — secrets/CI substrate rollout (Supply-Chain Hardening)
# ----------------------------------------------------------------------------
# Enforces that every `uses:` GitHub Action in .github/workflows/*.yml is pinned
# to a FULL 40-hex commit SHA (not a mutable @vN tag or @branch). Blocks the
# tag-mutability / branch-HEAD supply-chain attack class (tj-actions, TanStack).
#
# PASS:  uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4.3.1
# FAIL:  uses: actions/checkout@v4          (version tag — mutable)
# FAIL:  uses: some/action@main             (branch — mutable)
# SKIP:  uses: ./.github/actions/local      (local composite action — no ref)
# SKIP:  uses: docker://image:tag           (docker ref — out of scope here)
#
# Exit 0 = all pinned. Exit 1 = unpinned refs found (printed).
# Run in CI (security job) and/or as a pre-commit check.
# ============================================================================
set -euo pipefail

WF_DIR="${1:-.github/workflows}"

if [[ ! -d "$WF_DIR" ]]; then
  echo "check-action-pins: no workflow dir at '$WF_DIR' — nothing to check."
  exit 0
fi

violations=""
# Gather every `uses:` line (handles `- uses:` and `uses:` forms).
while IFS= read -r entry; do
  file="${entry%%:*}"
  line="${entry#*:}"
  # Extract the ref token (first whitespace-delimited word after `uses:`).
  ref="$(printf '%s' "$line" | sed -E 's/.*uses:[[:space:]]*//' | awk '{print $1}')"
  [[ -z "$ref" ]] && continue
  case "$ref" in
    ./*|docker://*) continue ;;        # local / docker — out of scope
  esac
  [[ "$ref" != *"@"* ]] && continue    # local composite action with no @ref
  sha="${ref##*@}"
  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    violations+="  ${file}:  ${ref}"$'\n'
  fi
done < <(grep -rEn --include='*.yml' --include='*.yaml' \
          '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^[:space:]]+' "$WF_DIR" 2>/dev/null || true)

if [[ -n "$violations" ]]; then
  echo "::error::Unpinned GitHub Action(s) found. Pin to a full commit SHA with a '# vX.Y.Z' comment."
  echo "Resolve a tag's SHA with: gh api repos/<owner>/<repo>/git/refs/tags/<tag>"
  echo
  printf '%s' "$violations"
  exit 1
fi

echo "check-action-pins: all GitHub Actions in $WF_DIR are SHA-pinned. ✓"
