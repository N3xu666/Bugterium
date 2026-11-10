import { describe, it, expect, beforeAll } from 'vitest';
import { aggregate } from '../src/lib/aggregate';
import type { GraphQLAccountData, MonitorResponse } from '../src/lib/types';
import fixture from './fixtures/graphql-response.json';

// Fixed `now` so timeline is deterministic. Aligns with the fixture's latest bucket (16:00Z).
const NOW = new Date('2026-11-10T16:30:00Z');

function getAccount(): GraphQLAccountData {
  return (fixture as { data: { viewer: { accounts: GraphQLAccountData[] } } }).data.viewer.accounts[0];
}

describe('aggregate() — v1 contract (frontend invariants F-01..F-05)', () => {
  let result: MonitorResponse;

  beforeAll(() => {
    result = aggregate(getAccount(), NOW);
  });

  it('produces a valid v1 response with all required top-level keys', () => {
    expect(result.status).toBe('ok');
    expect(result.timestamp).toBe(NOW.toISOString());
    // v1 contract — every key must exist (F-01..F-05 depend on these names)
    expect(result).toHaveProperty('security_metrics');
    expect(result).toHaveProperty('status_breakdown');
    expect(result).toHaveProperty('geo_data');
    expect(result).toHaveProperty('attacks_by_country');
    expect(result).toHaveProperty('timeline');
    expect(result).toHaveProperty('path_data');
    expect(result).toHaveProperty('user_agent_data');
  });

  it('security_metrics matches expected totals', () => {
    const m = result.security_metrics;
    expect(m.worker_requests_24h).toBe(1500);
    expect(m.worker_errors_24h).toBe(3);
    expect(m.blocked_403).toBe(10);
    expect(m.blocked_429).toBe(0);
    expect(m.client_errors_4xx).toBe(17); // 403(10) + 404(7)
    expect(m.server_errors_5xx).toBe(5);  // 500(3) + 504(2)
    expect(m.health_percent).toBe('97.2'); // (770/792*100).toFixed(1)
  });

  it('F-01 geo_data: [{country, count}], sorted desc, Unknown excluded', () => {
    expect(result.geo_data).toEqual([
      { country: 'US', count: 559 }, // 500+50+7+2
      { country: 'AZ', count: 203 }, // 200+3
      { country: 'NL', count: 10 },
    ]);
    // F-04: Unknown filter applied
    expect(result.geo_data.some((g) => g.country === 'Unknown')).toBe(false);
  });

  it('F-02 attacks_by_country: [{country, count}], 403/404/429 only, sorted desc', () => {
    expect(result.attacks_by_country).toEqual([
      { country: 'NL', count: 10 }, // 403
      { country: 'US', count: 7 },  // 404
    ]);
    expect(result.attacks_by_country.some((g) => g.country === 'Unknown')).toBe(false);
  });

  it('timeline: 24 hourly buckets ending at NOW, fixture hours distributed correctly', () => {
    expect(result.timeline).toHaveLength(24);
    expect(result.timeline[23]).toEqual({ hour: '2026-11-10T16:00:00.000Z', count: 150 });
    expect(result.timeline[22]).toEqual({ hour: '2026-11-10T15:00:00.000Z', count: 200 });
    expect(result.timeline[21]).toEqual({ hour: '2026-11-10T14:00:00.000Z', count: 100 });
    // Other 21 buckets: 0
    const zeroCount = result.timeline.filter((t) => t.count === 0).length;
    expect(zeroCount).toBe(21);
  });

  it('F-03 path_data.attacks: only attack-regex matches, byPath order preserved', () => {
    expect(result.path_data.attacks).toEqual([
      { path: '/wp-login.php', count: 7 },
      { path: '/.env', count: 3 },
    ]);
  });

  it('F-03 path_data.benign: non-matches (incl. 32-hex, per current classifier)', () => {
    // Current behavior: 32-hex path does NOT match ATTACK_PATH_REGEX → benign.
    // (Future classifier may re-classify; M-05 §9 mask planned in Phase 2/3.)
    expect(result.path_data.benign).toEqual([
      { path: '/', count: 400 },
      { path: '/monitor', count: 300 },
      { path: '/placeholder-path', count: 2 },
    ]);
  });

  it('F-03 path_data.correlations: {path: {country: count}}, Unknown excluded', () => {
    expect(result.path_data.correlations).toEqual({
      '/': { US: 300, AZ: 100 },
      '/monitor': { US: 200, AZ: 100 },
      '/wp-login.php': { NL: 7 },
      '/.env': { US: 3 },
    });
  });

  it('F-03 user_agent_data.traffic: sorted desc by count', () => {
    expect(result.user_agent_data.traffic).toEqual([
      { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0', count: 700 },
      { ua: 'curl/8.0', count: 200 },
      { ua: 'Mozilla/5.0 (compatible; Googlebot/2.1)', count: 100 },
      { ua: 'Unknown', count: 5 },
    ]);
  });

  it('F-03 user_agent_data.attacks: only 403/404/429', () => {
    expect(result.user_agent_data.attacks).toEqual([
      { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0', count: 7 },
      { ua: 'curl/8.0', count: 3 },
      { ua: 'sqlmap/1.7', count: 2 },
    ]);
  });

  it('status_breakdown: 18 entries (16 initial + 200 + 304), sorted desc by count', () => {
    expect(result.status_breakdown).toHaveLength(18);
    // Top entries sorted by count desc, stable
    expect(result.status_breakdown[0]).toEqual({ code: 200, count: 720 });
    expect(result.status_breakdown[1]).toEqual({ code: 304, count: 50 });
    expect(result.status_breakdown[2]).toEqual({ code: 403, count: 10 });
    expect(result.status_breakdown[3]).toEqual({ code: 404, count: 7 });
    expect(result.status_breakdown[4]).toEqual({ code: 500, count: 3 });
    expect(result.status_breakdown[5]).toEqual({ code: 504, count: 2 });
    // Pre-seeded codes with zero count are still present
    const zeroCodes = result.status_breakdown
      .filter((s) => s.count === 0)
      .map((s) => s.code)
      .sort((a, b) => a - b);
    expect(zeroCodes).toEqual([400, 401, 405, 413, 414, 422, 429, 451, 501, 502, 503, 505]);
  });

  it('F-05 fresh arrays per call (visual restart trigger preserved)', () => {
    const r1 = aggregate(getAccount(), NOW);
    const r2 = aggregate(getAccount(), NOW);
    // Deep equal
    expect(r1).toEqual(r2);
    // But different references — triggers React effects on each update
    expect(r1.geo_data).not.toBe(r2.geo_data);
    expect(r1.timeline).not.toBe(r2.timeline);
    expect(r1.path_data).not.toBe(r2.path_data);
    expect(r1.path_data.attacks).not.toBe(r2.path_data.attacks);
  });
});