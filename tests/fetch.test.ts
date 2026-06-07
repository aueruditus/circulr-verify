// tests/fetch.test.ts
//
// Locks fetchJwk against the LIVE verification-keys.{env}.json shape, which wraps
// each key as { id, status, valid_from, public_key_jwk: {kty,crv,x,y} } and
// carries the identifier in `id` (top-level `kid` is null) — NOT a flat JWK keyed
// by `kid`. Regression guard for the P7 verify-leg finding (4 Jun 2026): manifest
// signature verification failed with "Key id absent from key set" because the
// lookup matched only top-level `kid` and never unwrapped public_key_jwk.

import { describe, expect, it } from 'vitest';
import { fetchJwk } from '../src/fetch.js';

const KID = 'circulr-platform-dev-2026-05';
const URL_ = 'https://keys.test/.well-known/verification-keys.json';
// Minimal EC P-256 JWK params; fetchJwk locates + unwraps but does not import them.
const JWK_PARAMS = { kty: 'EC', crv: 'P-256', x: 'x-coord', y: 'y-coord' };

function keysetFetcher(body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;
}

describe('fetchJwk keyset parsing', () => {
  it('accepts the live wrapper shape ({ id, public_key_jwk }, kid null) and unwraps the JWK', async () => {
    const fetcher = keysetFetcher({
      keys: [
        { id: KID, status: 'active', environment: 'dev', public_key_jwk: { ...JWK_PARAMS, kid: null } },
        { id: 'circulr-l2-dev-2026-05', status: 'active', public_key_jwk: { ...JWK_PARAMS } },
      ],
    });
    const jwk = await fetchJwk(URL_, KID, fetcher);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.x).toBe('x-coord');
    expect(jwk.y).toBe('y-coord');
  });

  it('still accepts a flat JWK keyed by top-level kid (fixture / standard shape)', async () => {
    const fetcher = keysetFetcher({ keys: [{ kid: KID, ...JWK_PARAMS }] });
    const jwk = await fetchJwk(URL_, KID, fetcher);
    expect(jwk.x).toBe('x-coord');
  });

  it('throws jwk_key_id_missing when neither id nor kid matches', async () => {
    const fetcher = keysetFetcher({ keys: [{ id: 'some-other-key', public_key_jwk: JWK_PARAMS }] });
    await expect(fetchJwk(URL_, KID, fetcher)).rejects.toThrow(/absent from key set/);
  });
});
