#!/usr/bin/env node
// src/index.ts
//
// `@circulr/verify` CLI entry point.

import { Command } from 'commander';
import { formatHuman, formatJson } from './report.js';
import { verify, type VerifyResult } from './verify.js';

const DEFAULT_ENDPOINT = 'https://circulrdesigner.circulr.ai';

interface CliOptions {
  programmeId: string;
  endpoint: string;
  tier: string;
  supabaseToken?: string;
  format: 'human' | 'json';
  verbose: boolean;
  version?: string;
}

/** sysexits.h convention. */
const EX_OK = 0;
const EX_MISMATCH = 1;
const EX_NOT_VERIFIABLE_YET = 2;
const EX_ARCHIVE_LOCKED = 3;
const EX_USAGE = 64;

function exitCodeFor(result: VerifyResult): number {
  switch (result.kind) {
    case 'verified':
      return EX_OK;
    case 'mismatch':
      return EX_MISMATCH;
    case 'not_verifiable_yet':
      return EX_NOT_VERIFIABLE_YET;
    case 'archive_locked':
      return EX_ARCHIVE_LOCKED;
  }
}

async function main(): Promise<void> {
  const program = new Command();

  program
    .name('circulr-verify')
    .description(
      'Independent verifier for au.com.auspost.sustainability §7 Computation Manifests. ' +
        'Anyone can verify Aggregation Integrity; programme participants can verify Input Integrity.',
    )
    .requiredOption('--programme-id <uuid>', 'Programme identifier to verify')
    .option('--endpoint <url>', 'API endpoint of the verifying platform', DEFAULT_ENDPOINT)
    .option('--tier <n>', 'Verification tier (1 = Aggregation Integrity, 2 = Input Integrity)', '1')
    .option(
      '--supabase-token <jwt>',
      'Programme-participant Supabase JWT. Required for --tier 2; if supplied without --tier 2, implies Tier 2.',
    )
    .option('--format <fmt>', 'Output format: human | json', 'human')
    .option('--verbose', 'Print canonical body, intermediate hashes, JWK, independence check', false)
    .option('--version <n>', 'Specific published_version to verify; defaults to latest')
    .helpOption('-h, --help', 'Show usage');

  program.parse(process.argv);
  const opts = program.opts() as CliOptions;

  // Argument validation.
  if (opts.format !== 'human' && opts.format !== 'json') {
    process.stderr.write(`Usage error: --format must be 'human' or 'json'\n`);
    process.exit(EX_USAGE);
  }

  let tierNum: 1 | 2;
  if (opts.tier === '1') tierNum = 1;
  else if (opts.tier === '2') tierNum = 2;
  else {
    process.stderr.write(`Usage error: --tier must be 1 or 2\n`);
    process.exit(EX_USAGE);
  }

  // Open Q7: --supabase-token without --tier 2 implies Tier 2.
  if (opts.supabaseToken && tierNum === 1) {
    if (opts.format === 'human') {
      process.stderr.write(
        'info: --supabase-token supplied; verifying at Tier 2 (Input Integrity).\n',
      );
    }
    tierNum = 2;
  }

  if (tierNum === 2 && !opts.supabaseToken) {
    process.stderr.write(
      `Usage error: --tier 2 requires --supabase-token <jwt> (programme-participant access).\n`,
    );
    process.exit(EX_USAGE);
  }

  const publishedVersion = opts.version ? Number(opts.version) : undefined;
  if (publishedVersion !== undefined && (!Number.isInteger(publishedVersion) || publishedVersion < 1)) {
    process.stderr.write(`Usage error: --version must be a positive integer\n`);
    process.exit(EX_USAGE);
  }

  // Run verification.
  const result = await verify({
    endpoint: opts.endpoint,
    programmeId: opts.programmeId,
    tier: tierNum,
    supabaseToken: opts.supabaseToken,
    publishedVersion,
  });

  if (opts.format === 'json') {
    process.stdout.write(JSON.stringify(formatJson(result, { programmeId: opts.programmeId }), null, 2) + '\n');
  } else {
    process.stdout.write(formatHuman(result, { verbose: opts.verbose, programmeId: opts.programmeId }) + '\n');
  }

  process.exit(exitCodeFor(result));
}

main().catch((err) => {
  process.stderr.write(`Unexpected error: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(EX_MISMATCH);
});
