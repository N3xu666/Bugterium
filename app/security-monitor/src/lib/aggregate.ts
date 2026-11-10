// Security Monitor — pure aggregation.
// Logic 1:1 from pre-refactor src/index.ts (lines 51..217), with these fixes:
//   - All variables declared BEFORE use (fixes TS2448/TS2454/TS2304)
//   - Typed GraphQL groups (fixes TS18046 for a.count/b.count)
//   - `now: Date` parameter for deterministic testing
// NO behavior changes: identical inputs -> identical v1 output.
// Frontend invariants F-01..F-05 preserved — see types.ts header.

import type {
  GraphQLAccountData,
  MonitorResponse,
  SecurityMetrics,
  StatusBreakdownItem,
  GeoDataItem,
  TimelineItem,
  PathItem,
  PathData,
  UserAgentData,
  UserAgentItem,
} from './types';

// Preserved verbatim from pre-refactor line 152 — drives client-side ONLY BOTS filter (F-03).
const ATTACK_PATH_REGEX =
  /(\.env|wp-admin|wp-login|phpmyadmin|xmlrpc|config|\.git|\.aws|\.ssh|admin|login|shell|api\/v1)/i;

// Pre-seeded status codes (pre-refactor line 114) — keep the breakdown shape stable.
const INITIAL_STATUS_MAP: Record<number, number> = {
  400: 0, 401: 0, 403: 0, 404: 0, 405: 0, 413: 0, 414: 0, 422: 0, 429: 0, 451: 0,
  500: 0, 501: 0, 502: 0, 503: 0, 504: 0, 505: 0,
};

// F-04: `country !== "Unknown"` filter preserved verbatim.
const UNKNOWN_COUNTRY = 'Unknown';
const UNKNOWN_UA = 'Unknown';

const HOUR_MS = 3_600_000;
const HOURS_IN_TIMELINE = 24;

export function aggregate(account: GraphQLAccountData, now: Date): MonitorResponse {
  const stats = account.workersInvocationsAdaptive ?? [];
  const httpGroups = account.byStatusCountry ?? [];
  const byHour = account.byHour ?? [];
  const byPath = account.byPath ?? [];
  const byPathCountry = account.byPathCountry ?? [];
  const byUserAgent = account.byUserAgent ?? [];

  // ---- Worker invocations ----
  let totalRequests = 0;
  let totalErrors = 0;
  for (const stat of stats) {
    totalRequests += stat.sum.requests || 0;
    totalErrors += stat.sum.errors || 0;
  }

  // ---- Status / country aggregation ----
  let blocked403 = 0;
  let blocked429 = 0;
  let clientErrors4xx = 0;
  let serverErrors5xx = 0;
  let success2xx = 0;
  let totalStatusCount = 0;
  const statusMap: Record<number, number> = { ...INITIAL_STATUS_MAP };
  const trafficByCountry: Record<string, number> = {};
  const attacksByCountry: Record<string, number> = {};

  for (const group of httpGroups) {
    const status = group.dimensions.edgeResponseStatus;
    const country = group.dimensions.clientCountryName || UNKNOWN_COUNTRY;

    if (status === 403) blocked403 += group.count;
    if (status === 429) blocked429 += group.count;

    totalStatusCount += group.count;
    statusMap[status] = (statusMap[status] || 0) + group.count;

    if (status >= 200 && status < 400) success2xx += group.count;
    if (status >= 400 && status < 500) clientErrors4xx += group.count;
    if (status >= 500) serverErrors5xx += group.count;

    if (country !== UNKNOWN_COUNTRY) {
      trafficByCountry[country] = (trafficByCountry[country] || 0) + group.count;

      // Attack classifier preserved verbatim (pre-refactor lines 137-140).
      if (status === 403 || status === 404 || status === 429) {
        attacksByCountry[country] = (attacksByCountry[country] || 0) + group.count;
      }
    }
  }

  const healthPercent =
    totalStatusCount > 0 ? ((success2xx / totalStatusCount) * 100).toFixed(1) : '100.0';

  const statusBreakdown: StatusBreakdownItem[] = Object.entries(statusMap)
    .map(([code, count]) => ({ code: Number(code), count }))
    .sort((a, b) => b.count - a.count);

  const geoData: GeoDataItem[] = Object.entries(trafficByCountry)
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count);

  const attackCountryData: GeoDataItem[] = Object.entries(attacksByCountry)
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count);

  // ---- Timeline: 24 hourly buckets ending at `now` (pre-refactor lines 83..97) ----
  const hourKey = (iso: string) => Math.floor(new Date(iso).getTime() / HOUR_MS);
  const hourlyMap: Record<number, number> = {};
  for (const group of byHour) {
    const key = hourKey(group.dimensions.datetimeHour);
    hourlyMap[key] = (hourlyMap[key] || 0) + group.count;
  }
  const currentHourKey = Math.floor(now.getTime() / HOUR_MS);
  const timeline: TimelineItem[] = [];
  for (let i = HOURS_IN_TIMELINE - 1; i >= 0; i--) {
    const key = currentHourKey - i;
    timeline.push({
      hour: new Date(key * HOUR_MS).toISOString(),
      count: hourlyMap[key] || 0,
    });
  }

  // ---- Paths (F-03: attack/benign split + correlations map) ----
  const pathData: PathItem[] = [];
  for (const g of byPath) {
    const p = g.dimensions.clientRequestPath;
    if (p) pathData.push({ path: p, count: g.count });
  }

  const attackPaths = pathData.filter((x) => ATTACK_PATH_REGEX.test(x.path));
  const benignPaths = pathData.filter((x) => !ATTACK_PATH_REGEX.test(x.path));

  const pathCountries: Record<string, Record<string, number>> = {};
  for (const g of byPathCountry) {
    const path = g.dimensions.clientRequestPath;
    const country = g.dimensions.clientCountryName;
    if (path && country && country !== UNKNOWN_COUNTRY) {
      if (!pathCountries[path]) pathCountries[path] = {};
      pathCountries[path][country] = (pathCountries[path][country] || 0) + g.count;
    }
  }

  const pathDataBlock: PathData = {
    attacks: attackPaths,
    benign: benignPaths,
    correlations: pathCountries,
  };

  // ---- User agents (F-03) ----
  const uaTraffic: Record<string, number> = {};
  const uaAttacks: Record<string, number> = {};
  for (const g of byUserAgent) {
    const ua = g.dimensions.userAgent || UNKNOWN_UA;
    const status = g.dimensions.edgeResponseStatus;
    if (status === 403 || status === 404 || status === 429) {
      uaAttacks[ua] = (uaAttacks[ua] || 0) + g.count;
    } else {
      uaTraffic[ua] = (uaTraffic[ua] || 0) + g.count;
    }
  }

  const mapAndSort = (obj: Record<string, number>): UserAgentItem[] =>
    Object.entries(obj)
      .map(([ua, count]) => ({ ua, count }))
      .sort((a, b) => b.count - a.count);

  const userAgentData: UserAgentData = {
    traffic: mapAndSort(uaTraffic),
    attacks: mapAndSort(uaAttacks),
  };

  // ---- Final assembly ----
  const securityMetrics: SecurityMetrics = {
    worker_requests_24h: totalRequests,
    worker_errors_24h: totalErrors,
    blocked_403: blocked403,
    blocked_429: blocked429,
    client_errors_4xx: clientErrors4xx,
    server_errors_5xx: serverErrors5xx,
    health_percent: healthPercent,
  };

  return {
    status: 'ok',
    timestamp: now.toISOString(),
    security_metrics: securityMetrics,
    status_breakdown: statusBreakdown,
    geo_data: geoData,
    attacks_by_country: attackCountryData,
    timeline,
    path_data: pathDataBlock,
    user_agent_data: userAgentData,
  };
}