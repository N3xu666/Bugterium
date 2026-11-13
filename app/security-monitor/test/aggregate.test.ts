import { describe, it, expect, beforeAll } from 'vitest';
import {
  aggregate,
  aggregateTraffic,
  aggregateProbes,
  classifyProbeFamily,
  sanitizeProbePath,
  classifyUaFamily,
  aggregateUaFamilies,
  aggregateErrors5xx,
  aggregateAuth,
  computeBaseline,
} from '../src/lib/aggregate';
import type {
  GraphQLAccountData,
  MonitorResponse,
  AggregateTrafficConfig,
  ProbesBreakdown,
  BaselineBreakdown,
} from '../src/lib/types';
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
describe('aggregateTraffic() — M-03 (v2): host split', () => {
  const ALL_CONFIG: AggregateTrafficConfig = {
    siteHost: 'bugterium.pages.dev',
    monitorHost: 'bugterium-monitor.workers.dev',
    bffHost: 'bugterium-bff.workers.dev',
  };

  it('splits byHost into site / own_polling / bff_requests / other_http', () => {
    const result = aggregateTraffic(getAccount(), ALL_CONFIG);
    expect(result.site_requests).toBe(350);
    expect(result.own_polling).toBe(200);
    expect(result.bff_requests).toBe(100);
    // other_http = totalHttp (670) - named (650) = 20 (external 15 + null 5)
    expect(result.other_http).toBe(20);
  });

  it('cron_invocations is 0 (deprecated); total_workers = raw Worker invocations', () => {
    const result = aggregateTraffic(getAccount(), ALL_CONFIG);
    // workersInvocationsAdaptive: 1000 + 500 = 1500; cron cannot be derived from byHost.
    expect(result.cron_invocations).toBe(0);
    expect(result.total_workers).toBe(1500);
  });

  it('hosts[] excludes null host and is sorted desc by count', () => {
    const result = aggregateTraffic(getAccount(), ALL_CONFIG);
    expect(result.hosts).toEqual([
      { host: 'bugterium.pages.dev', count: 350 },
      { host: 'bugterium-monitor.workers.dev', count: 200 },
      { host: 'bugterium-bff.workers.dev', count: 100 },
      { host: 'external.api.example.com', count: 15 },
    ]);
    expect(result.hosts.find((h) => h.host === '')).toBeUndefined();
  });

  it('empty config => site/own/bff = 0, other_http = 670, cron = 0, total_workers = 1500', () => {
    const result = aggregateTraffic(getAccount(), {});
    expect(result.site_requests).toBe(0);
    expect(result.own_polling).toBe(0);
    expect(result.bff_requests).toBe(0);
    expect(result.other_http).toBe(670);
    expect(result.cron_invocations).toBe(0);
    expect(result.total_workers).toBe(1500);
  });

  it('works with missing byHost (older snapshots)', () => {
    const account = { ...getAccount(), byHost: undefined };
    const result = aggregateTraffic(account, ALL_CONFIG);
    expect(result.site_requests).toBe(0);
    expect(result.other_http).toBe(0);
    expect(result.cron_invocations).toBe(0);
    expect(result.total_workers).toBe(1500);
    expect(result.hosts).toEqual([]);
  });
});


describe('aggregateProbes() — M-04 (v2): probe outcome split', () => {
  it('total equals sum of all HTTP status counts', () => {
    const result: ProbesBreakdown = aggregateProbes(getAccount());
    expect(result.total).toBe(792);
  });

  it('by_outcome splits: reached / not_found / blocked / error', () => {
    const { by_outcome } = aggregateProbes(getAccount());
    expect(by_outcome.reached).toBe(770);   // 2xx(770) + 3xx
    expect(by_outcome.not_found).toBe(7);   // 404
    expect(by_outcome.blocked).toBe(10);    // 403(10) + 429(0)
    expect(by_outcome.error).toBe(5);       // 500(3) + 504(2) + other 5xx
  });

  it('invariant: total = reached + not_found + blocked + error', () => {
    const r = aggregateProbes(getAccount());
    const sum = r.by_outcome.reached + r.by_outcome.not_found + r.by_outcome.blocked + r.by_outcome.error;
    expect(sum).toBe(r.total);
  });

  it('top_paths sorted desc, null filtered, capped at 20', () => {
    const { top_paths } = aggregateProbes(getAccount());
    expect(top_paths).toEqual([
      { path: '/', count: 400 },
      { path: '/monitor', count: 300 },
      { path: '/wp-login.php', count: 7 },
      { path: '/.env', count: 3 },
      { path: '/placeholder-path', count: 2 },
    ]);
    expect(top_paths.every((p) => p.path !== null)).toBe(true);
    expect(top_paths.length).toBeLessThanOrEqual(20);
  });

  it('masks 32-hex paths in top_paths as [hex32]', () => {
    const hex32Path = '/' + 'a'.repeat(32);
    const account: GraphQLAccountData = {
      ...getAccount(),
      byPath: [
        { count: 50, dimensions: { clientRequestPath: hex32Path } },
        { count: 10, dimensions: { clientRequestPath: '/normal-path' } },
      ],
    };
    const { top_paths } = aggregateProbes(account);
    expect(top_paths).toEqual([
      { path: '/[hex32]', count: 50 },
      { path: '/normal-path', count: 10 },
    ]);
  });

  it('empty byStatusCountry => all outcomes 0, total 0', () => {
    const account: GraphQLAccountData = { ...getAccount(), byStatusCountry: [] };
    const r = aggregateProbes(account);
    expect(r.total).toBe(0);
    expect(r.by_outcome).toEqual({ reached: 0, not_found: 0, blocked: 0, error: 0 });
  });
});


describe('classifyProbeFamily() — M-06 (v2): family signatures', () => {
  const CASES: Array<[string, string | null]> = [
    ['/.env', 'env_file'],
    ['/.env.local', 'env_file'],
    ['/wp-login.php', 'wordpress'],
    ['/wp-admin/setup.php', 'wordpress'],
    ['/phpmyadmin/index.php', 'phpmyadmin'],
    ['/.git/config', 'git'],
    ['/.aws/credentials', 'aws_creds'],
    ['/.ssh/id_rsa', 'ssh_keys'],
    ['/shell.php', 'shell'],
    ['/phpinfo.php', 'phpinfo'],
    ['/cgi-bin/test.cgi', 'cgi_bin'],
    ['/actuator/env', 'actuator'],    // Pass 197: recon-driven signatures (svn, ds_store, spip, hex32 ownership probes)
    ['/.svn/wc.db', 'svn'],
    ['/.DS_Store', 'ds_store'],
    ['/spip.php', 'spip'],
    ['/3f82ae4a120302071f40250be8c2d6ec', 'hex32_probe'],
    // High-confidence-only: legit paths must NOT be flagged as families
    ['/admin/dashboard', null],
    ['/auth/login', null],
    ['/api/v1/users', null],
    ['/', null],
    ['', null],
  ];

  it.each(CASES)('classifies %s => %s', (path, expected) => {
    expect(classifyProbeFamily(path)).toBe(expected);
  });
});

describe('aggregateProbes().families — M-06 (v2): per-family aggregation', () => {
  it('groups fixture bad paths by family, sorted desc by count', () => {
    const { families } = aggregateProbes(getAccount());
    // Fixture: /wp-login.php (7), /.env (3), /placeholder-path (2, no match), / (400, no match)
    expect(families).toEqual([
      { family: 'wordpress', count: 7 },
      { family: 'env_file', count: 3 },
    ]);
  });

  it('families total is a subset of non-reached probes (invariant)', () => {
    const r = aggregateProbes(getAccount());
    const familyTotal = r.families.reduce((sum, f) => sum + f.count, 0);
    const suspicious = r.by_outcome.not_found + r.by_outcome.blocked + r.by_outcome.error;
    expect(familyTotal).toBeLessThanOrEqual(suspicious);
  });

  it('empty byPath => families is empty array', () => {
    const account: GraphQLAccountData = { ...getAccount(), byPath: [] };
    const r = aggregateProbes(account);
    expect(r.families).toEqual([]);
  });
});

describe('sanitizeProbePath() — M-05/M-06 privacy sanitization', () => {
  it('masks 32-hex path as /[hex32]', () => {
    expect(sanitizeProbePath('/' + 'b'.repeat(32))).toBe('/[hex32]');
    expect(sanitizeProbePath('/' + '0'.repeat(32))).toBe('/[hex32]');
  });

  it('preserves normal paths intact', () => {
    expect(sanitizeProbePath('/')).toBe('/');
    expect(sanitizeProbePath('/monitor')).toBe('/monitor');
    expect(sanitizeProbePath('/wp-login.php')).toBe('/wp-login.php');
  });

  it('masks 32-hex paths inside aggregate().path_data.benign and correlations', () => {
    const hexPathA = '/' + 'a'.repeat(32);
    const hexPathB = '/' + 'f'.repeat(32);
    const account: GraphQLAccountData = {
      ...getAccount(),
      byPath: [
        { count: 12, dimensions: { clientRequestPath: hexPathA } },
        { count: 8, dimensions: { clientRequestPath: hexPathB } },
        { count: 100, dimensions: { clientRequestPath: '/' } },
      ],
      byPathCountry: [
        { count: 12, dimensions: { clientRequestPath: hexPathA, clientCountryName: 'US' } },
        { count: 8, dimensions: { clientRequestPath: hexPathB, clientCountryName: 'US' } },
      ],
    };
    const res = aggregate(account, NOW);
    expect(res.path_data.benign).toEqual([
      { path: '/[hex32]', count: 20 },
      { path: '/', count: 100 },
    ]);
    expect(res.path_data.correlations['/[hex32]']).toEqual({ US: 20 });
    expect(res.path_data.correlations[hexPathA]).toBeUndefined();
  });
});

describe('UA classifier, traffic estimates, errors_5xx, auth, baseline (Contract v2)', () => {
  it('classifies UA families accurately', () => {
    expect(classifyUaFamily('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0')).toBe('browser');
    expect(classifyUaFamily('curl/8.0')).toBe('automation');
    expect(classifyUaFamily('Mozilla/5.0 (compatible; Googlebot/2.1)')).toBe('crawler');
    expect(classifyUaFamily('sqlmap/1.7')).toBe('scanner');
    expect(classifyUaFamily(null)).toBe('unknown');
  });

  it('aggregateUaFamilies groups fixture user agents', () => {
    const families = aggregateUaFamilies(getAccount());
    expect(families).toEqual([
      { family: 'browser', count: 707 },
      { family: 'automation', count: 203 },
      { family: 'crawler', count: 100 },
      { family: 'unknown', count: 5 },
      { family: 'scanner', count: 2 },
    ]);
  });

  it('aggregateTraffic populates human_est, bot_est, scanner_est', () => {
    const t = aggregateTraffic(getAccount(), {});
    expect(t.human_est).toBe(707);
    expect(t.bot_est).toBe(303);
    expect(t.scanner_est).toBe(2);
  });

  it('aggregateErrors5xx separates platform (504) vs app (500) errors', () => {
    const errs = aggregateErrors5xx(getAccount());
    expect(errs.total).toBe(5);
    expect(errs.platform_5xx).toBe(2);
    expect(errs.app_5xx).toBe(3);
    expect(errs.by_code).toEqual([
      { code: 500, count: 3, classification: 'app' },
      { code: 504, count: 2, classification: 'platform' },
    ]);
    expect(errs.by_cache).toEqual([
      { status: 'MISS', count: 2 },
      { status: 'DYNAMIC', count: 3 },
    ]);
    expect(errs.by_origin_status).toEqual([
      { code: 0, count: 2 },
      { code: 500, count: 3 },
    ]);
  });

  it('aggregateAuth distributes D1 auth_events into 24h buckets and totals', () => {
    const h16 = Math.floor(new Date('2026-11-10T16:00:00Z').getTime() / 1000);
    const h14 = Math.floor(new Date('2026-11-10T14:00:00Z').getTime() / 1000);
    const auth = aggregateAuth(
      [
        { hour_epoch: h16, event: 'login_success', count: 4 },
        { hour_epoch: h16, event: 'forbidden', count: 2 },
        { hour_epoch: h14, event: 'login_fail', count: 1 },
        { hour_epoch: h14, event: 'logout', count: 3 },
      ],
      NOW,
    );
    expect(auth.by_hour).toHaveLength(24);
    expect(auth.totals).toEqual({ login_success: 4, login_fail: 1, forbidden: 2, logout: 3 });
    expect(auth.by_hour[23]).toEqual({
      hour: '2026-11-10T16:00:00.000Z',
      login_success: 4,
      login_fail: 0,
      forbidden: 2,
      logout: 0,
    });
    expect(auth.by_hour[21]).toEqual({
      hour: '2026-11-10T14:00:00.000Z',
      login_success: 0,
      login_fail: 1,
      forbidden: 0,
      logout: 3,
    });
  });

  it('computeBaseline merges previous 24h history and computes spike ratio', () => {
    const prev: BaselineBreakdown = {
      current_24h: 150,
      previous_24h: 0,
      ratio: 1.0,
      level: 'normal',
      hourly_history: [
        { hour: '2026-11-09T10:00:00.000Z', count: 150 },
      ],
    };
    const b = computeBaseline(getAccount(), NOW, prev);
    expect(b.current_24h).toBe(450); // 100 + 200 + 150 from fixture
    expect(b.previous_24h).toBe(150);
    expect(b.ratio).toBe(3.0);
    expect(b.level).toBe('critical');
    expect(b.hourly_history).toHaveLength(4);

    // Re-running with the resulting baseline must NOT double-count current 24h buckets
    const b2 = computeBaseline(getAccount(), NOW, b);
    expect(b2.current_24h).toBe(450);
    expect(b2.previous_24h).toBe(150);
  });
});