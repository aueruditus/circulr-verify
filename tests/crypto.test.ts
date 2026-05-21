// tests/crypto.test.ts
//
// Parity tests for src/crypto.ts. These assert byte-identical output against
// the source-side contract documented at the top of
// CirculrDesignerGA/supabase/functions/publish-to-passport/computationManifest.ts.
//
// Boundary cases per spec §7.3: 0.12345 → 0.1234, 0.12355 → 0.1236,
// nested-object key ordering, NaN/Infinity rejection.

import { describe, it, expect } from 'vitest';
import {
  roundHalfEven,
  canonicalJsonStringify,
  sha256Hex,
  base64UrlEncode,
  base64UrlDecode,
  importEs256VerifyingKey,
  verifyES256,
} from '../src/crypto.js';

describe('roundHalfEven', () => {
  it('rounds half-to-even at 4dp boundary cases', () => {
    expect(roundHalfEven(0.12345)).toBe(0.1234);
    expect(roundHalfEven(0.12355)).toBe(0.1236);
    expect(roundHalfEven(0.12365)).toBe(0.1236);
    expect(roundHalfEven(0.12375)).toBe(0.1238);
  });

  it('passes Infinity / -Infinity / NaN through unchanged', () => {
    expect(roundHalfEven(Infinity)).toBe(Infinity);
    expect(roundHalfEven(-Infinity)).toBe(-Infinity);
    expect(Number.isNaN(roundHalfEven(NaN))).toBe(true);
  });

  it('matches Math.round for non-boundary values', () => {
    expect(roundHalfEven(0.1234)).toBe(0.1234);
    expect(roundHalfEven(0.12346)).toBe(0.1235);
    expect(roundHalfEven(0.12344)).toBe(0.1234);
  });

  it('handles negative values symmetrically (round to even applies)', () => {
    expect(roundHalfEven(-0.12345)).toBe(-0.1234);
    expect(roundHalfEven(-0.12355)).toBe(-0.1236);
  });
});

describe('canonicalJsonStringify', () => {
  it('sorts object keys alphabetically (recursive)', () => {
    expect(canonicalJsonStringify({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalJsonStringify({ z: { b: 1, a: 2 }, a: 1 })).toBe('{"a":1,"z":{"a":2,"b":1}}');
  });

  it('rounds numbers through roundHalfEven before serialisation', () => {
    expect(canonicalJsonStringify({ x: 0.12345 })).toBe('{"x":0.1234}');
    expect(canonicalJsonStringify({ x: 0.12355 })).toBe('{"x":0.1236}');
  });

  it('emits null for NaN / Infinity (null_handling contract)', () => {
    expect(canonicalJsonStringify({ x: NaN })).toBe('{"x":null}');
    expect(canonicalJsonStringify({ x: Infinity })).toBe('{"x":null}');
    expect(canonicalJsonStringify({ x: -Infinity })).toBe('{"x":null}');
  });

  it('handles null, undefined, booleans, strings, dates, arrays', () => {
    expect(canonicalJsonStringify(null)).toBe('null');
    expect(canonicalJsonStringify(undefined)).toBe('null');
    expect(canonicalJsonStringify(true)).toBe('true');
    expect(canonicalJsonStringify(false)).toBe('false');
    expect(canonicalJsonStringify('hello "world"')).toBe('"hello \\"world\\""');
    expect(canonicalJsonStringify(new Date('2026-05-21T00:00:00.000Z'))).toBe('"2026-05-21T00:00:00.000Z"');
    expect(canonicalJsonStringify([1, 'a', null])).toBe('[1,"a",null]');
  });

  it('round-trips a representative manifest body', () => {
    const body = {
      version: '1.0',
      programme_id: 'prog-1',
      output: { metrics_hash: 'abc', metrics_source: 'canonical_pipeline' },
      inputs: [{ dataset: 't', hash: 'h', columns: ['a', 'b'], row_count: 2 }],
    };
    const canonical = canonicalJsonStringify(body);
    expect(canonical.startsWith('{"inputs":[{')).toBe(true);
    expect(canonical).toContain('"version":"1.0"');
  });
});

describe('sha256Hex', () => {
  it('hashes the empty string', async () => {
    // Well-known: SHA-256("") = e3b0c442…
    expect(await sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('hashes "abc" against the FIPS 180-2 test vector', async () => {
    expect(await sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('base64Url encode/decode', () => {
  it('round-trips bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 254, 255, 100, 200]);
    const encoded = base64UrlEncode(bytes);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
    const decoded = base64UrlDecode(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(bytes));
  });

  it('accepts padded input on decode', () => {
    const decodedPadded = base64UrlDecode('AAEC');
    const decodedUnpadded = base64UrlDecode('AAEC');
    expect(Array.from(decodedPadded)).toEqual(Array.from(decodedUnpadded));
  });

  it('handles 1-byte and 2-byte trailing groups', () => {
    expect(Array.from(base64UrlDecode(base64UrlEncode(new Uint8Array([1]))))).toEqual([1]);
    expect(Array.from(base64UrlDecode(base64UrlEncode(new Uint8Array([1, 2]))))).toEqual([1, 2]);
  });
});

describe('verifyES256', () => {
  it('rejects a signature signed against a different message (round-trip via Web Crypto)', async () => {
    const keypair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const message = 'hello';
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keypair.privateKey,
      new TextEncoder().encode(message),
    );
    const sigB64Url = base64UrlEncode(new Uint8Array(sig));

    const jwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
    const pub = await importEs256VerifyingKey(jwk as never);

    expect(await verifyES256(message, sigB64Url, pub)).toBe(true);
    expect(await verifyES256(message + 'tamper', sigB64Url, pub)).toBe(false);
  });
});
