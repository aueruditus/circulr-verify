// tests/recompute.test.ts
//
// Unit tests for the version-gated canonical_pipeline net-sign (SPEC_CirculrVerify_Reuse_Recompute
// Arm A). Pins the displacement-as-benefit gate: from producer function_version 4.x the verifier
// must credit co2e_type='displacement' (matching CDGA publish-to-passport canonicalPipelineMetrics),
// while archived pre-4.x manifests reproduce with displacement as a burden (the signed convention).

import { describe, it, expect } from 'vitest';
import { recomputeCanonicalPipeline, recomputeForSource } from '../src/recompute.js';

const REUSE_ROWS = [
  { co2e_type: 'avoided', co2e_kg: 10 },
  { co2e_type: 'displacement', co2e_kg: 105 },
  { co2e_type: 'processing', co2e_kg: 20 },
];

describe('recomputeCanonicalPipeline — displacement net-sign gate', () => {
  it('credits displacement as a benefit when creditDisplacement=true (function_version >= 4.1.0)', () => {
    const m = recomputeCanonicalPipeline(REUSE_ROWS, true);
    // benefit = avoided(10) + displacement(105) = 115; burden = processing(20)
    expect(m.net_carbon_impact_kg).toBe(95); // 115 - 20
    expect(m.carbon_payback_ratio).toBe(5.75); // 115 / 20
  });

  it('treats displacement as a burden when creditDisplacement=false (archived pre-4.1.0 convention)', () => {
    const m = recomputeCanonicalPipeline(REUSE_ROWS, false);
    // avoided(10) - [processing(20) + displacement(105)] = -115
    expect(m.net_carbon_impact_kg).toBe(-115);
  });

  it('defaults to the archival (burden) convention when the flag is omitted', () => {
    const m = recomputeCanonicalPipeline(REUSE_ROWS);
    expect(m.net_carbon_impact_kg).toBe(-115);
  });

  it('material rows (no displacement) are identical regardless of the flag', () => {
    const material = [
      { co2e_type: 'processing', co2e_kg: 193.024 },
      { co2e_type: 'avoided', co2e_kg: 34.684 },
    ];
    const credited = recomputeCanonicalPipeline(material, true);
    const legacy = recomputeCanonicalPipeline(material, false);
    expect(credited.net_carbon_impact_kg).toBe(legacy.net_carbon_impact_kg);
    expect(credited.net_carbon_impact_kg).toBe(-158.34); // GAR-CEL: 34.684 - 193.024
  });
});

describe('recomputeForSource — threads the gate to canonical_pipeline', () => {
  it('credits displacement for canonical_pipeline when creditDisplacement=true', () => {
    const m = recomputeForSource('canonical_pipeline', REUSE_ROWS, true);
    expect(m.net_carbon_impact_kg).toBe(95);
  });

  it('does not credit displacement when the flag is false', () => {
    const m = recomputeForSource('canonical_pipeline', REUSE_ROWS, false);
    expect(m.net_carbon_impact_kg).toBe(-115);
  });
});
