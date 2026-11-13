import { describe, it, expect } from 'vitest';
import {
  aggregate,
  aggregateProbes,
  aggregateTraffic,
  aggregateAttackerNetworks,
  aggregateSpecialSources,
  sanitizeProbePath,
  sanitizeTelemetryText,
} from '../src/lib/aggregate';
import { buildSnapshot } from '../src/lib/snapshot';
import type { GraphQLAccountData } from '../src/lib/types';

const NOW = new Date('2026-11-14T00:00:00Z');

function makeEmptyAccount(): GraphQLAccountData {
  return {
    workersInvocationsAdaptive: [{ sum: { requests: 10, errors: 0 } }],
    byStatusCountry: [],
    byHour: [{ count: 10, dimensions: { datetimeHour: '2026-11-14T00:00:00Z' } }],
    byPath: [],
    byPathCountry: [],
    byUserAgent: [],
    byHost: [],
    byAsn: [],
  };
}

// Deterministic PRNG (Mulberry32) so fuzz runs are 100% reproducible in CI.
function createRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const HOSTILE_ALPHABET = [
  '/', 'a', 'b', '0', '9', '-', '_', '.', '?', '&', '=', '#',
  '<', '>', '"', "'", '%', '3', 'c', 'e',
  '\x00', '\x07', '\x0a', '\x0d', '\x1b', '\x1f', '\x7f',
  '\u202e', '\u202a', '\u2066', '\u200f', '\u200e', '\u2603',
  '<script>', '</script>', 'script', 'alert(1)', '__proto__', 'constructor',
];

function randomHostileString(rng: () => number, minLen: number, maxLen: number): string {
  const targetLen = minLen + Math.floor(rng() * (maxLen - minLen + 1));
  let out = '';
  while (out.length < targetLen) {
    out += HOSTILE_ALPHABET[Math.floor(rng() * HOSTILE_ALPHABET.length)];
  }
  return out;
}

describe('TD #42 Phase 3: sanitizeProbePath() & input fuzzing', () => {
  it('strips <script>, angle brackets, and %3c/%3e encodings', () => {
    const xssPaths = [
      '/<script>alert(1)</script>',
      '/search/%3Cscript%3Ealert(1)%3C/script%3E',
      '/<img src=x onerror=alert(1)>',
      '/path?next=<script>evil()</script>',
    ];
    for (const p of xssPaths) {
      const cleaned = sanitizeProbePath(p);
      expect(cleaned).not.toContain('<');
      expect(cleaned).not.toContain('>');
      expect(cleaned.toLowerCase()).not.toContain('%3c');
      expect(cleaned.toLowerCase()).not.toContain('%3e');
      expect(cleaned.toLowerCase()).not.toContain('<script>');
    }
  });

  it('caps 10KB+ paths to max 120 chars cleanly', () => {
    const tenKbPath = '/' + 'z'.repeat(10_240);
    const cleaned = sanitizeProbePath(tenKbPath);
    expect(cleaned.length).toBeLessThanOrEqual(120);
    expect(cleaned).toBe('/' + 'z'.repeat(119));

    const tenKbHex = '/' + 'a'.repeat(10_240);
    expect(sanitizeProbePath(tenKbHex)).toBe('/[hex]');
  });

  it('strips ASCII control chars (\\x00-\\x1f, \\x7f) and RTL unicode (\\u202e etc.)', () => {
    const hostile = '/\x00admin\x07\x0a\x0d\x1b[31m\x1f/exec\u202e\u2066\u200f\x7f.php';
    const cleaned = sanitizeProbePath(hostile);
    expect(cleaned).toBe('/admin[31m/exec.php');
    // eslint-disable-next-line no-control-regex
    expect(/[\u0000-\u001f\u007f-\uffff<>]/.test(cleaned)).toBe(false);
  });

  it('returns safe placeholder when input contains only stripped chars', () => {
    expect(sanitizeProbePath('\x00\x01\u202e<>')).toBe('/[sanitized]');
  });

  it('strips query strings and fragments before masking 32-hex / UUID / long hex', () => {
    const hex32 = 'b'.repeat(32);
    const hex48 = 'c'.repeat(48);
    expect(sanitizeProbePath('/.env?token=secret&debug=1#top')).toBe('/.env');
    expect(sanitizeProbePath(`/${hex32}?probe=1`)).toBe('/[hex32]');
    expect(sanitizeProbePath(`/items/${hex32}/detail`)).toBe('/items/[hex32]/detail');
    expect(sanitizeProbePath(`/${hex48}`)).toBe('/[hex]');
    expect(sanitizeProbePath('/users/550e8400-e29b-41d4-a716-446655440000/profile')).toBe(
      '/users/[uuid]/profile',
    );
  });

  it('bounds sanitizeTelemetryText across oversized and hostile strings', () => {
    const raw = `\x00\u202e<script>${'Z'.repeat(500)}</script>`;
    const res = sanitizeTelemetryText(raw, 80);
    expect(res.length).toBe(80);
    expect(res).not.toContain('<');
    expect(res).not.toContain('\x00');
    expect(res).not.toContain('\u202e');
  });

  it('guards against prototype pollution keys in aggregate() correlations & countries', () => {
    const account = makeEmptyAccount();
    account.byStatusCountry = [
      { count: 5, dimensions: { edgeResponseStatus: 404, clientCountryName: '__proto__' } },
      { count: 3, dimensions: { edgeResponseStatus: 404, clientCountryName: 'constructor' } },
    ];
    account.byPath = [
      { count: 4, dimensions: { clientRequestPath: '__proto__' } },
    ];
    account.byPathCountry = [
      { count: 4, dimensions: { clientRequestPath: '__proto__', clientCountryName: 'US' } },
      { count: 4, dimensions: { clientRequestPath: '/ok', clientCountryName: '__proto__' } },
    ];
    account.byUserAgent = [
      { count: 4, dimensions: { userAgent: 'constructor', edgeResponseStatus: 403 } },
    ];

    const res = aggregate(account, NOW);
    expect(({} as Record<string, unknown>).US).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(res.path_data.correlations, '__proto__')).toBe(false);
    expect(res.geo_data.some((g) => g.country === '__proto__' || g.country === 'constructor')).toBe(false);
    expect(res.user_agent_data.attacks).toEqual([]);
  });

  it('fuzz loop (250 hostile randomized cases): invariants hold and zero unsafe chars leak to snapshot JSON', () => {
    const rng = createRng(0x5eed201);

    for (let i = 0; i < 250; i++) {
      const account = makeEmptyAccount();
      const hostilePath = '/' + randomHostileString(rng, 10, i % 10 === 0 ? 10_500 : 300);
      const hostileUa = randomHostileString(rng, 5, i % 15 === 0 ? 10_240 : 400);
      const hostileHost = randomHostileString(rng, 3, 400);
      const hostileAsnDesc = randomHostileString(rng, 5, 300);
      const hostileCountry = randomHostileString(rng, 2, 40);

      account.byStatusCountry = [
        { count: 7, dimensions: { edgeResponseStatus: 404, clientCountryName: hostileCountry } },
        { count: 3, dimensions: { edgeResponseStatus: 200, clientCountryName: 'US' } },
      ];
      account.byPath = [{ count: 7, dimensions: { clientRequestPath: hostilePath } }];
      account.byPathCountry = [
        { count: 7, dimensions: { clientRequestPath: hostilePath, clientCountryName: 'US' } },
      ];
      account.byUserAgent = [{ count: 7, dimensions: { userAgent: hostileUa, edgeResponseStatus: 404 } }];
      account.byHost = [{ count: 7, dimensions: { clientRequestHTTPHost: hostileHost } }];
      account.byAsn = [
        {
          count: 7,
          dimensions: { clientAsn: 64512, clientASNDescription: hostileAsnDesc, edgeResponseStatus: 404 },
        },
      ];

      const snapshot = buildSnapshot(account, {
        windowStart: new Date(NOW.getTime() - 86_400_000),
        windowEnd: NOW,
        trafficConfig: { siteHost: 'bugterium.pages.dev' },
      });

      const probes = snapshot.probes!;
      expect(probes.total).toBe(
        probes.by_outcome.reached +
          probes.by_outcome.not_found +
          probes.by_outcome.blocked +
          probes.by_outcome.error,
      );

      for (const item of snapshot.path_data.attacks.concat(snapshot.path_data.benign)) {
        expect(item.path.length).toBeLessThanOrEqual(120);
      }

      const serialized = JSON.stringify(snapshot);
      // JSON serialization of control/RTL/script markers must be completely sanitized.
      expect(serialized).not.toContain('<script>');
      expect(serialized).not.toContain('\u202e');
      expect(serialized).not.toContain('\u0000');
      expect(serialized).not.toContain('\\u0000');
      expect(serialized).not.toContain('\\u202e');
    }
  });
});

describe('TD #42 Phase 2.5: aggregateAttackerNetworks() & aggregateSpecialSources()', () => {
  it('aggregates probe statuses (403/404/429) by ASN, enforces k >= 5, ignores 200/304', () => {
    const account = makeEmptyAccount();
    account.byAsn = [
      { count: 4, dimensions: { clientAsn: 14061, clientASNDescription: 'DIGITALOCEAN-ASN', edgeResponseStatus: 404 } },
      { count: 3, dimensions: { clientAsn: 14061, clientASNDescription: 'DIGITALOCEAN-ASN', edgeResponseStatus: 403 } },
      { count: 12, dimensions: { clientAsn: 16509, clientASNDescription: 'AMAZON-02\u202e<script>', edgeResponseStatus: 403 } },
      // Benign 200 status must NOT enter attacker_networks even if count >= 5
      { count: 500, dimensions: { clientAsn: 15169, clientASNDescription: 'GOOGLE', edgeResponseStatus: 200 } },
      // Below k >= 5 threshold -> suppressed for k-anonymity
      { count: 4, dimensions: { clientAsn: 24940, clientASNDescription: 'HETZNER-AS', edgeResponseStatus: 404 } },
      // Null/invalid ASN ignored
      { count: 20, dimensions: { clientAsn: null, clientASNDescription: 'BAD', edgeResponseStatus: 404 } },
    ];

    const networks = aggregateAttackerNetworks(account);
    expect(networks).toEqual([
      { asn: 16509, description: 'AMAZON-02script', count: 12 },
      { asn: 14061, description: 'DIGITALOCEAN-ASN', count: 7 },
    ]);
  });

  it('separates T1 (Tor) and XX/null/Unknown special sources accurately', () => {
    const account = makeEmptyAccount();
    account.byStatusCountry = [
      { count: 100, dimensions: { edgeResponseStatus: 200, clientCountryName: 'US' } },
      { count: 6, dimensions: { edgeResponseStatus: 403, clientCountryName: 'T1' } },
      { count: 4, dimensions: { edgeResponseStatus: 200, clientCountryName: 'T1' } },
      { count: 8, dimensions: { edgeResponseStatus: 404, clientCountryName: 'XX' } },
      { count: 3, dimensions: { edgeResponseStatus: 200, clientCountryName: null } },
    ];

    const special = aggregateSpecialSources(account);
    expect(special).toEqual({
      tor_requests: 10,
      unknown_geo: 11,
      total: 21,
      by_code: [
        { country: 'XX', count: 11 },
        { country: 'T1', count: 10 },
      ],
    });
  });

  it('buildSnapshot includes attacker_networks and special_sources on v2 snapshot', () => {
    const account = makeEmptyAccount();
    account.byStatusCountry = [
      { count: 7, dimensions: { edgeResponseStatus: 403, clientCountryName: 'T1' } },
    ];
    account.byAsn = [
      { count: 9, dimensions: { clientAsn: 9009, clientASNDescription: 'M247', edgeResponseStatus: 403 } },
    ];
    const snap = buildSnapshot(account, {
      windowStart: new Date(NOW.getTime() - 86_400_000),
      windowEnd: NOW,
    });
    expect(snap.attacker_networks).toEqual([{ asn: 9009, description: 'M247', count: 9 }]);
    expect(snap.special_sources).toEqual({
      tor_requests: 7,
      unknown_geo: 0,
      total: 7,
      by_code: [{ country: 'T1', count: 7 }],
    });
    expect(aggregateTraffic(account, {}).scanner_est).toBe(0);
  });
});
