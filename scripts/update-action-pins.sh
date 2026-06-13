#!/usr/bin/env bash
# ============================================================================
# update-action-pins.sh — secrets/CI substrate rollout (Supply-Chain Hardening)
# ----------------------------------------------------------------------------
# REVIEW-ONLY. For each SHA-pinned `uses: owner/repo@<sha>  # vX.Y.Z` in the
# workflows, query the action repo's latest release (fallback: newest tag) and
# its commit SHA, and print whether an update is available. Does NOT modify any
# file — it surfaces what needs human review.
#
# Run quarterly, or when a Dependabot github-actions PR flags a new version.
# Requires an authenticated `gh`.
#
# Usage: scripts/update-action-pins.sh [workflow-dir]
# ============================================================================
set -euo pipefail

WF_DIR="${1:-.github/workflows}"

command -v gh >/dev/null 2>&1 || { echo "update-action-pins: requires the 'gh' CLI (authenticated)."; exit 2; }

echo "Checking SHA-pinned actions for available updates (review-only)…"
echo

# Extract unique "owner/repo@sha  # comment" triples from live workflows.
grep -rhoE --include='*.yml' --include='*.yaml' \
  'uses:[[:space:]]*[^@[:space:]]+@[0-9a-f]{40}[[:space:]]*#[[:space:]]*[^[:space:]]+' "$WF_DIR" 2>/dev/null \
  | sed -E 's/uses:[[:space:]]*//' \
  | sort -u \
  | while IFS= read -r line; do
      ref="$(printf '%s' "$line" | awk '{print $1}')"
      repo="${ref%@*}"
      sha="${ref##*@}"
      comment="$(printf '%s' "$line" | sed -E 's/^[^#]*#[[:space:]]*//')"

      # Latest release tag, fallback to newest tag.
      tag="$(gh api "repos/$repo/releases/latest" --jq '.tag_name' 2>/dev/null || true)"
      [[ -z "$tag" ]] && tag="$(gh api "repos/$repo/tags?per_page=1" --jq '.[0].name' 2>/dev/null || true)"
      if [[ -z "$tag" ]]; then
        printf '  ?  %-34s  could not query latest (branch-based or private?) — check by hand\n' "$repo"
        continue
      fi

      latest_sha="$(gh api "repos/$repo/commits/$tag" --jq '.sha' 2>/dev/null || true)"
      if [[ -z "$latest_sha" ]]; then
        printf '  ?  %-34s  could not resolve %s\n' "$repo" "$tag"
      elif [[ "$latest_sha" == "$sha" ]]; then
        printf '  ok %-34s  up to date (%s)\n' "$repo" "$comment"
      else
        printf '  UP %-34s  %s (%s)  ->  %s %s\n' \
          "$repo" "${sha:0:12}" "$comment" "$tag" "${latest_sha:0:12}"
      fi
    done

echo
echo "Review each 'UP' line, then update the pin SHA + '# version' comment by hand"
echo "(or merge the corresponding Dependabot github-actions PR, which bumps both)."
echo "Re-run scripts/check-action-pins.sh after any edit to confirm pins remain valid."
