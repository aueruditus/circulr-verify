// src/report.ts
//
// Output formatters. Human + JSON.
//
// Capitalisation contract (AC13): "Aggregation Integrity" and "Input Integrity"
// are protocol terms with proper-noun capitalisation throughout user-facing
// surfaces. They are NOT descriptive prose.

import chalk from 'chalk';
import type { ClaimLevel } from './crypto.js';
import type { PathwayVerdict, VerifyResult } from './verify.js';

function claimDisplay(claim: ClaimLevel): string {
  return claim === 'input_integrity' ? 'Input Integrity' : 'Aggregation Integrity';
}

/** One-line human summary of the separate pathway verdict (AC5). */
function pathwayLine(p: PathwayVerdict): string {
  switch (p.status) {
    case 'verified':
      return chalk.green('✓ pathway breakdown VERIFIED') +
        (p.projection_checked ? ' (recompute + L2 projection)' : ' (recompute; no L2 projection)');
    case 'mismatch':
      return chalk.red('✗ pathway breakdown MISMATCH');
    case 'not_verifiable_yet':
      return chalk.yellow('! pathway breakdown NOT_VERIFIABLE_YET') +
        (p.reason ? chalk.dim(` (${p.reason})`) : '');
  }
}

/**
 * Suggest the command that would establish the stronger claim. Used in
 * stronger_claim_command (JSON) and the human-output footer.
 */
function strongerClaimCommand(programmeId: string): string {
  return `npx @circulr/verify --programme-id ${programmeId} --tier 2 --supabase-token $TOKEN`;
}

// =============================================================================
// Human formatter
// =============================================================================

export function formatHuman(result: VerifyResult, opts: { verbose: boolean; programmeId: string }): string {
  const lines: string[] = [];

  switch (result.kind) {
    case 'verified': {
      const claim = claimDisplay(result.claim).toUpperCase();
      lines.push(chalk.green(`✓ ${claim} VERIFIED`));
      lines.push('');
      lines.push(`Programme:        ${result.context.programme_id}`);
      lines.push(`Published vers.:  ${result.context.published_version}`);
      lines.push(`Manifest version: ${result.context.manifest_version}`);
      lines.push(`Computed at:      ${result.context.computed_at}`);
      lines.push(
        `Public key:       ${result.context.public_key_id} @ ${result.context.public_key_url}`,
      );
      lines.push(`Metrics source:   ${result.context.metrics_source}`);
      lines.push(`Manifest source:  ${result.context.manifest_source}`);
      lines.push('');
      lines.push('Checks performed:');
      for (const c of result.context.checks) {
        const mark = c.passed ? chalk.green('✓') : chalk.red('✗');
        let line = `  ${mark} ${c.name.replaceAll('_', ' ')}`;
        if (c.algorithm) line += ` (${c.algorithm})`;
        if (c.tolerance_dp !== undefined) line += ` (${c.tolerance_dp}dp tolerance)`;
        if (c.tier !== undefined) line += ` (tier=${c.tier})`;
        lines.push(line);
      }

      // Legacy metrics_hash binding degrade — honest, not a failure (AC4).
      if (result.context.metrics_hash_binding_note) {
        lines.push('');
        lines.push(chalk.yellow('! metrics_hash binding NOT_REPRODUCIBLE (legacy whole-row binding)'));
        lines.push(chalk.dim(`  ${result.context.metrics_hash_binding_note}`));
      }
      // v3.0.0+ self-contained binding verified, but endpoint serialisation drifts.
      if (result.context.metrics_presentation_drift_note) {
        lines.push('');
        lines.push(chalk.yellow('! endpoint metrics presentation drift (soft note)'));
        lines.push(chalk.dim(`  ${result.context.metrics_presentation_drift_note}`));
      }

      // Pathway breakdown — reported separately from the scalar claim (AC5).
      if (result.context.pathway) {
        lines.push('');
        lines.push(pathwayLine(result.context.pathway));
        if (result.context.pathway.status !== 'verified' && result.context.pathway.detail) {
          lines.push(chalk.dim(`  ${result.context.pathway.detail}`));
        }
      }

      // Manifest-declared vs verifier-established (per AC20).
      if (result.context.manifest_claim_level !== result.claim) {
        lines.push('');
        lines.push(
          chalk.yellow(
            `Note: manifest declares ${claimDisplay(result.context.manifest_claim_level)}, ` +
              `but this verifier established ${claimDisplay(result.claim)} (verifier-side reports what it actually checked).`,
          ),
        );
      }

      // Stronger-claim footer (AC14 / spec §5.4 — suppressed at Tier 2).
      if (result.tier_run === 1) {
        lines.push('');
        lines.push(
          `For Input Integrity verification, run with --tier 2 --supabase-token $TOKEN`,
        );
        lines.push(`(requires programme-participant access).`);
      }

      // Verbose extras.
      if (opts.verbose) {
        lines.push('');
        lines.push(chalk.dim('— verbose —'));
        if (result.context.independence_check) {
          const ic = result.context.independence_check;
          lines.push('Independence check:');
          lines.push(`  determined_level: ${claimDisplay(ic.determined_level)}`);
          lines.push(`  measurement_platform: ${ic.measurement_platform_id || '(unset)'}`);
          lines.push(`  attestor:             ${ic.attestor_id || '(unset)'}`);
          lines.push(`  certifiers:           ${ic.certifier_ids.join(', ') || '(none)'}`);
          if (ic.non_independent_pairs.length > 0) {
            lines.push(`  non_independent_pairs:`);
            for (const p of ic.non_independent_pairs) {
              lines.push(`    ${p.left} ↔ ${p.right}  (shared_id=${p.shared_id})`);
            }
          } else {
            lines.push(`  non_independent_pairs: (none)`);
          }
        } else {
          lines.push('Independence check: not present on this manifest');
        }
        if (result.context.recomputed) {
          lines.push('Recomputed metric values:');
          for (const f of result.context.recomputed.recomputed_fields) {
            lines.push(`  ${f}: ${result.context.recomputed[f]}`);
          }
        }
        if (result.context.pathway_block) {
          lines.push('Signed pathway_outputs[] block:');
          for (const e of result.context.pathway_block) {
            lines.push(`  ${e.r_strategy}/${e.loop_type}: events=${e.events} kg=${e.kg} rate=${e.rate}`);
          }
        }
      }
      break;
    }

    case 'mismatch': {
      lines.push(chalk.red(`✗ MISMATCH at ${result.failed_at}`));
      lines.push('');
      lines.push(result.detail);
      lines.push('');
      lines.push(`Programme:        ${result.context.programme_id}`);
      lines.push(`Published vers.:  ${result.context.published_version}`);
      lines.push(`Manifest source:  ${result.context.manifest_source}`);
      lines.push('');
      lines.push('Checks performed:');
      for (const c of result.context.checks) {
        const mark = c.passed ? chalk.green('✓') : chalk.red('✗');
        const tail = c.passed === false ? ` — ${c.detail}` : '';
        lines.push(`  ${mark} ${c.name.replaceAll('_', ' ')}${tail}`);
      }
      break;
    }

    case 'not_verifiable_yet': {
      lines.push(chalk.yellow(`! NOT_VERIFIABLE_YET (${result.manifest_state})`));
      lines.push('');
      lines.push(result.detail);
      if (result.manifest_state === 'key_pending') {
        lines.push('');
        lines.push(
          'The manifest body exists but the signing key was not yet provisioned in this environment ' +
            'when this version was published. This is the H5.02 rollout key-pending window — wait for ' +
            'keys to land in the target environment.',
        );
      }
      break;
    }

    case 'archive_locked': {
      lines.push(chalk.yellow(`! ARCHIVE_LOCKED`));
      lines.push('');
      lines.push(result.detail);
      lines.push(`Existing function_version:  ${result.existing_function_version}`);
      lines.push(`Requested function_version: ${result.requested_function_version}`);
      break;
    }
  }

  return lines.join('\n');
}

// =============================================================================
// JSON formatter
// =============================================================================

export function formatJson(result: VerifyResult, opts: { programmeId: string }): unknown {
  switch (result.kind) {
    case 'verified': {
      const stronger = result.tier_run === 1;
      return {
        result: 'verified',
        claim: result.claim,
        tier_run: result.tier_run,
        stronger_claim_available: stronger,
        stronger_claim_command: stronger ? strongerClaimCommand(opts.programmeId) : null,
        programme_id: result.context.programme_id,
        published_version: result.context.published_version,
        manifest_version: result.context.manifest_version,
        computed_at: result.context.computed_at,
        metrics_source: result.context.metrics_source,
        public_key: {
          id: result.context.public_key_id,
          url: result.context.public_key_url,
        },
        manifest_source: result.context.manifest_source,
        checks: result.context.checks.map((c) => ({
          name: c.name,
          passed: c.passed,
          ...(c.algorithm ? { algorithm: c.algorithm } : {}),
          ...(c.tolerance_dp !== undefined ? { tolerance_dp: c.tolerance_dp } : {}),
          ...(c.tier !== undefined ? { tier: c.tier } : {}),
          ...(c.expected ? { expected: c.expected } : {}),
          ...(c.actual ? { actual: c.actual } : {}),
          ...(!c.passed ? { detail: c.detail } : {}),
        })),
        manifest_claim_level: result.context.manifest_claim_level,
        independence_check: result.context.independence_check,
        pathway: result.context.pathway ?? null,
        metrics_hash_binding_note: result.context.metrics_hash_binding_note ?? null,
        metrics_presentation_drift_note: result.context.metrics_presentation_drift_note ?? null,
      };
    }
    case 'mismatch':
      return {
        result: 'mismatch',
        failed_at: result.failed_at,
        detail: result.detail,
        tier_run: result.tier_run,
        programme_id: result.context.programme_id,
        published_version: result.context.published_version,
        checks: result.context.checks.map((c) => ({
          name: c.name,
          passed: c.passed,
          ...(c.algorithm ? { algorithm: c.algorithm } : {}),
          ...(c.tier !== undefined ? { tier: c.tier } : {}),
          ...(c.expected ? { expected: c.expected } : {}),
          ...(c.actual ? { actual: c.actual } : {}),
          ...(!c.passed ? { detail: c.detail } : {}),
        })),
        manifest_claim_level: result.context.manifest_claim_level,
        pathway: result.context.pathway ?? null,
      };
    case 'not_verifiable_yet':
      return {
        result: 'not_verifiable_yet',
        manifest_state: result.manifest_state,
        detail: result.detail,
        ...(result.published_version !== undefined
          ? { published_version: result.published_version }
          : {}),
      };
    case 'archive_locked':
      return {
        result: 'archive_locked',
        existing_function_version: result.existing_function_version,
        requested_function_version: result.requested_function_version,
        detail: result.detail,
      };
  }
}
