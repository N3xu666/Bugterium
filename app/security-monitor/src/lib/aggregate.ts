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
  TrafficBreakdown,
  AggregateTrafficConfig,
  HostTrafficItem,
  ProbesBreakdown,
  ProbesOutcome,
  ProbesFamily,
  UaFamilyName,
  UaFamilyItem,
  Error5xxCodeItem,
  Errors5xxBreakdown,
  AuthEventInput,
  AuthHourItem,
  AuthBreakdown,
  BaselineLevel,
  BaselineBreakdown,
  AttackerNetworkItem,
  SpecialSourcesBreakdown,
} from './types';

const MAX_PROBE_PATH_LEN = 120;
const MAX_UA_LEN = 256;
const MAX_HOST_LEN = 255;
const MAX_ASN_DESC_LEN = 80;
const MAX_COUNTRY_LEN = 16;
const PROBE_ATTACK_STATUSES = new Set<number>([403, 404, 429]);

function isSafeRecordKey(key: string): boolean {
  return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';
}

// Strips ASCII control chars, non-ASCII / RTL bidi overrides (\u202e etc.), and angle brackets < >.
export function sanitizeTelemetryText(input: string, maxLen: number): string {
  // eslint-disable-next-line no-control-regex
  const cleaned = input.replace(/[\u0000-\u001f\u007f-\uffff<>]/g, '');
  return cleaned.length > maxLen ? cleaned.slice(0, maxLen) : cleaned;
}

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
    const rawCountry = group.dimensions.clientCountryName;
    const cleanedCountry = rawCountry ? sanitizeTelemetryText(rawCountry, MAX_COUNTRY_LEN) : '';
    const country = cleanedCountry || UNKNOWN_COUNTRY;

    if (status === 403) blocked403 += group.count;
    if (status === 429) blocked429 += group.count;

    totalStatusCount += group.count;
    statusMap[status] = (statusMap[status] || 0) + group.count;

    if (status >= 200 && status < 400) success2xx += group.count;
    if (status >= 400 && status < 500) clientErrors4xx += group.count;
    if (status >= 500) serverErrors5xx += group.count;

    if (country !== UNKNOWN_COUNTRY && isSafeRecordKey(country)) {
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

  // ---- Paths (F-03: attack/benign split + correlations map, with [hex32] privacy mask) ----
  const pathCountMap = new Map<string, number>();
  for (const g of byPath) {
    const p = g.dimensions.clientRequestPath;
    if (p) {
      const sanitized = sanitizeProbePath(p);
      pathCountMap.set(sanitized, (pathCountMap.get(sanitized) || 0) + g.count);
    }
  }
  const pathData: PathItem[] = Array.from(pathCountMap.entries()).map(([path, count]) => ({ path, count }));

  const attackPaths = pathData.filter((x) => ATTACK_PATH_REGEX.test(x.path));
  const benignPaths = pathData.filter((x) => !ATTACK_PATH_REGEX.test(x.path));

  const pathCountries: Record<string, Record<string, number>> = {};
  for (const g of byPathCountry) {
    const rawPath = g.dimensions.clientRequestPath;
    const rawCountry = g.dimensions.clientCountryName;
    const country = rawCountry ? sanitizeTelemetryText(rawCountry, MAX_COUNTRY_LEN) : '';
    if (rawPath && country && country !== UNKNOWN_COUNTRY && isSafeRecordKey(country)) {
      const path = sanitizeProbePath(rawPath);
      if (!isSafeRecordKey(path)) continue;
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
    const rawUa = g.dimensions.userAgent;
    const sanitizedUa = rawUa ? sanitizeTelemetryText(rawUa, MAX_UA_LEN) : '';
    const ua = sanitizedUa || UNKNOWN_UA;
    if (!isSafeRecordKey(ua)) continue;
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
// M-03 (v2): Traffic breakdown by HTTP host. Splits site / monitor (own polling) /
// BFF / other from total Worker invocations. Returns zeros if byHost is missing
// (caller should only attach `traffic` to SnapshotResponse when byHost was queried).
export function aggregateTraffic(
  account: GraphQLAccountData,
  config: AggregateTrafficConfig,
): TrafficBreakdown {
  const stats = account.workersInvocationsAdaptive ?? [];
  const byHost = account.byHost ?? [];

  let totalWorkerRequests = 0;
  for (const s of stats) totalWorkerRequests += s.sum.requests || 0;

  let siteRequests = 0;
  let ownPolling = 0;
  let bffRequests = 0;
  let totalHttp = 0;
  const hosts: HostTrafficItem[] = [];

  for (const g of byHost) {
    const rawHost = g.dimensions.clientRequestHTTPHost ?? '';
    const host = sanitizeTelemetryText(rawHost, MAX_HOST_LEN);
    totalHttp += g.count;
    if (host) hosts.push({ host, count: g.count });
    if (config.siteHost && host === config.siteHost) siteRequests += g.count;
    else if (config.monitorHost && host === config.monitorHost) ownPolling += g.count;
    else if (config.bffHost && host === config.bffHost) bffRequests += g.count;
  }

  hosts.sort((a, b) => b.count - a.count);

  const namedHttp = siteRequests + ownPolling + bffRequests;
  const otherHttp = Math.max(0, totalHttp - namedHttp);

  // Pass 196 fix (M-03 tail): cron_invocations cannot be computed reliably.
  // workersInvocationsAdaptive.sum.requests (Workers only) and httpRequestsAdaptiveGroups
  // (all HTTP, incl. Pages static) are DIFFERENT datasets; subtracting yields negative
  // (clamped to 0). Keep the field at 0 for v2 contract compat; expose raw total_workers.
  const cronInvocations = 0;

  // P2.4: UA-estimated human / bot / scanner breakdown from byUserAgent.
  let humanEst = 0;
  let botEst = 0;
  let scannerEst = 0;
  for (const g of account.byUserAgent ?? []) {
    const fam = classifyUaFamily(g.dimensions.userAgent);
    if (fam === 'browser') humanEst += g.count;
    else if (fam === 'crawler' || fam === 'automation') botEst += g.count;
    else if (fam === 'scanner') scannerEst += g.count;
  }

  return {
    site_requests: siteRequests,
    own_polling: ownPolling,
    bff_requests: bffRequests,
    other_http: otherHttp,
    cron_invocations: cronInvocations,
    total_workers: totalWorkerRequests,
    hosts,
    human_est: humanEst,
    bot_est: botEst,
    scanner_est: scannerEst,
  };
}


// M-06 (v2): Probe family signatures (high-confidence patterns only).
// Additive: does NOT replace ATTACK_PATH_REGEX (v1 path_data.attacks).
// Only known bad-path families -> no false-positive on /admin, /login, /config, /api/v1.
export const PROBE_FAMILIES: ReadonlyArray<{ family: string; pattern: RegExp }> = [
  { family: 'env_file',   pattern: /(\.env(\.|$)|\.envrc)/i },
  { family: 'wordpress',  pattern: /(wp-admin|wp-login|wp-content|wp-includes)/i },
  { family: 'phpmyadmin', pattern: /phpmyadmin/i },
  { family: 'git',        pattern: /\.git(\/|$)/i },
  { family: 'aws_creds',  pattern: /\.aws(\/|$)/i },
  { family: 'ssh_keys',   pattern: /\.ssh(\/|$)/i },
  { family: 'shell',      pattern: /(shell\.(php|sh|cgi)|c99|r57)/i },
  { family: 'phpinfo',    pattern: /phpinfo\.php/i },
  { family: 'cgi_bin',    pattern: /cgi-bin\//i },
  { family: 'actuator',   pattern: /\/actuator(\/|$)/i },  // Pass 197: expanded signature set from live recon (svn, ds_store, spip, hex32 ownership probes)
  { family: 'svn',        pattern: /\.svn(\/|$)/i },
  { family: 'ds_store',   pattern: /\.ds_store$/i },
  { family: 'spip',       pattern: /spip\.php/i },
  { family: 'hex32_probe',pattern: /^\/[0-9a-f]{32}$/i },
];

export function classifyProbeFamily(path: string): string | null {
  if (!path) return null;
  for (const f of PROBE_FAMILIES) {
    if (f.pattern.test(path)) return f.family;
  }
  return null;
}

// M-05/M-06 & TD #42 privacy/security sanitization (§12.D):
// strip query/fragment, strip control/non-ASCII/RTL/<>/%3c/%3e, mask UUIDs & long hex, cap at 120 chars.
export function sanitizeProbePath(path: string): string {
  const withoutQuery = path.split(/[?#]/, 1)[0] ?? '';
  const withoutEncodedAngles = withoutQuery.replace(/%3[ce]/gi, '');
  let cleaned = sanitizeTelemetryText(withoutEncodedAngles, withoutQuery.length);
  if (/^\/[0-9a-f]{32}$/i.test(cleaned)) {
    return '/[hex32]';
  }
  cleaned = cleaned
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '[uuid]')
    .replace(/(^|\/)[0-9a-f]{32}(?=\/|$)/gi, '$1[hex32]')
    .replace(/(^|\/)[0-9a-f]{33,}(?=\/|$)/gi, '$1[hex]');
  if (!cleaned) {
    return '/[sanitized]';
  }
  return cleaned.length > MAX_PROBE_PATH_LEN ? cleaned.slice(0, MAX_PROBE_PATH_LEN) : cleaned;
}
// M-04 (v2): Probe outcome split. Fixes "SUSPICIOUS = 100% - (2xx+3xx)".
// Separates attack signals (not_found + blocked) from infrastructure errors (error).
// Invariant: total = reached + not_found + blocked + error.
export function aggregateProbes(account: GraphQLAccountData): ProbesBreakdown {
  const httpGroups = account.byStatusCountry ?? [];
  const byPath = account.byPath ?? [];

  let total = 0;
  let reached = 0;
  let notFound = 0;
  let blocked = 0;
  let error = 0;

  for (const g of httpGroups) {
    const status = g.dimensions.edgeResponseStatus;
    total += g.count;
    if (status >= 200 && status < 400) reached += g.count;
    else if (status === 404) notFound += g.count;
    else if (status === 403 || status === 429) blocked += g.count;
    else error += g.count;
  }

  const pathMap = new Map<string, number>();
  for (const g of byPath) {
    const p = g.dimensions.clientRequestPath;
    if (p) {
      const sanitized = sanitizeProbePath(p);
      pathMap.set(sanitized, (pathMap.get(sanitized) || 0) + g.count);
    }
  }
  const top_paths: PathItem[] = Array.from(pathMap.entries())
    .map(([path, count]) => ({ path, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  const by_outcome: ProbesOutcome = {
    reached,
    not_found: notFound,
    blocked,
    error,
  };

  const familyCounts: Record<string, number> = {};
  for (const g of byPath) {
    const p = g.dimensions.clientRequestPath;
    if (!p) continue;
    const fam = classifyProbeFamily(p);
    if (fam) familyCounts[fam] = (familyCounts[fam] || 0) + g.count;
  }
  const families: ProbesFamily[] = Object.entries(familyCounts)
    .map(([family, count]) => ({ family, count }))
    .sort((a, b) => b.count - a.count);

  return { total, by_outcome, top_paths, families };
}

// P2.4 (v2): User-Agent family classifier (no raw UA exposed).
const UA_SCANNER_RE =
  /(sqlmap|nikto|nmap|masscan|nuclei|ffuf|dirb|dirbuster|gobuster|feroxbuster|httpx|zgrab|censys|shodan|expanse|wpscan|acunetix|nessus|burp)/i;
const UA_CRAWLER_RE =
  /(googlebot|bingbot|yandexbot|duckduckbot|baiduspider|slurp|facebot|ia_archiver|applebot|semrushbot|ahrefsbot|mj12bot|bot|crawl|spider)/i;
const UA_AUTOMATION_RE =
  /(curl|wget|python|go-http|java\/|okhttp|axios|node-fetch|libwww|httpie|postman|insomnia|headless|phantom|puppet|selenium|playwright)/i;
const UA_BROWSER_RE = /(mozilla\/5\.0.*(chrome|safari|firefox|edg|opr)|opera)/i;

export function classifyUaFamily(ua: string | null | undefined): UaFamilyName {
  if (!ua || ua === UNKNOWN_UA) return 'unknown';
  if (UA_SCANNER_RE.test(ua)) return 'scanner';
  if (UA_CRAWLER_RE.test(ua)) return 'crawler';
  if (UA_AUTOMATION_RE.test(ua)) return 'automation';
  if (UA_BROWSER_RE.test(ua)) return 'browser';
  return 'unknown';
}

export function aggregateUaFamilies(account: GraphQLAccountData): UaFamilyItem[] {
  const byUserAgent = account.byUserAgent ?? [];
  const counts: Record<UaFamilyName, number> = {
    browser: 0,
    automation: 0,
    scanner: 0,
    crawler: 0,
    unknown: 0,
  };
  for (const g of byUserAgent) {
    const fam = classifyUaFamily(g.dimensions.userAgent);
    counts[fam] += g.count;
  }
  return (Object.entries(counts) as Array<[UaFamilyName, number]>)
    .filter(([, count]) => count > 0)
    .map(([family, count]) => ({ family, count }))
    .sort((a, b) => b.count - a.count);
}

// P2.5 & M-05 (v2): Separate platform 5xx (502/503/504, cache=MISS, origin=0) from app 5xx.
const PLATFORM_5XX_CODES = new Set<number>([502, 503, 504]);

export function aggregateErrors5xx(account: GraphQLAccountData): Errors5xxBreakdown {
  const httpGroups = account.byStatusCountry ?? [];
  const codeCounts = new Map<number, number>();
  let total = 0;
  let platform5xx = 0;
  let app5xx = 0;

  for (const g of httpGroups) {
    const status = g.dimensions.edgeResponseStatus;
    if (status >= 500 && status < 600) {
      total += g.count;
      codeCounts.set(status, (codeCounts.get(status) || 0) + g.count);
      if (PLATFORM_5XX_CODES.has(status)) {
        platform5xx += g.count;
      } else {
        app5xx += g.count;
      }
    }
  }

  const by_code: Error5xxCodeItem[] = Array.from(codeCounts.entries())
    .map(([code, count]) => ({
      code,
      count,
      classification: PLATFORM_5XX_CODES.has(code) ? ('platform' as const) : ('app' as const),
    }))
    .sort((a, b) => b.count - a.count || a.code - b.code);

  const by_cache: Array<{ status: string; count: number }> = [];
  if (platform5xx > 0) by_cache.push({ status: 'MISS', count: platform5xx });
  if (app5xx > 0) by_cache.push({ status: 'DYNAMIC', count: app5xx });

  const by_origin_status: Array<{ code: number; count: number }> = [];
  if (platform5xx > 0) by_origin_status.push({ code: 0, count: platform5xx });
  for (const item of by_code) {
    if (item.classification === 'app') {
      by_origin_status.push({ code: item.code, count: item.count });
    }
  }

  return {
    total,
    platform_5xx: platform5xx,
    app_5xx: app5xx,
    by_code,
    by_cache,
    by_origin_status,
  };
}

// P1.1 (v2): Aggregate D1 auth_events into 24 hourly buckets + totals (0 PII).
export function aggregateAuth(events: AuthEventInput[], now: Date): AuthBreakdown {
  const currentHourKey = Math.floor(now.getTime() / HOUR_MS);
  const bucketMap = new Map<number, AuthHourItem>();

  for (let i = HOURS_IN_TIMELINE - 1; i >= 0; i--) {
    const key = currentHourKey - i;
    bucketMap.set(key, {
      hour: new Date(key * HOUR_MS).toISOString(),
      login_success: 0,
      login_fail: 0,
      forbidden: 0,
      logout: 0,
    });
  }

  const totals = {
    login_success: 0,
    login_fail: 0,
    forbidden: 0,
    logout: 0,
  };

  for (const ev of events) {
    const key = Math.floor(ev.hour_epoch / 3600);
    const bucket = bucketMap.get(key);
    if (!bucket) continue;
    if (ev.event === 'login_success') {
      bucket.login_success += ev.count;
      totals.login_success += ev.count;
    } else if (ev.event === 'login_fail') {
      bucket.login_fail += ev.count;
      totals.login_fail += ev.count;
    } else if (ev.event === 'forbidden') {
      bucket.forbidden += ev.count;
      totals.forbidden += ev.count;
    } else if (ev.event === 'logout') {
      bucket.logout += ev.count;
      totals.logout += ev.count;
    }
  }

  return {
    totals,
    by_hour: Array.from(bucketMap.values()),
  };
}

// P1.1 (v2): Rolling 48h baseline stored inside snapshot:latest (0 extra KV writes).
const HOURS_IN_BASELINE = 48;

export function computeBaseline(
  account: GraphQLAccountData,
  now: Date,
  prevBaseline?: BaselineBreakdown,
): BaselineBreakdown {
  const currentHourKey = Math.floor(now.getTime() / HOUR_MS);
  const minKey = currentHourKey - (HOURS_IN_BASELINE - 1);
  const splitKey = currentHourKey - (HOURS_IN_TIMELINE - 1);

  const merged = new Map<number, number>();
  for (const item of prevBaseline?.hourly_history ?? []) {
    const key = Math.floor(new Date(item.hour).getTime() / HOUR_MS);
    if (!Number.isNaN(key) && key >= minKey && key <= currentHourKey) {
      merged.set(key, item.count);
    }
  }
  const currentByHour = new Map<number, number>();
  for (const g of account.byHour ?? []) {
    const key = Math.floor(new Date(g.dimensions.datetimeHour).getTime() / HOUR_MS);
    if (!Number.isNaN(key) && key >= minKey && key <= currentHourKey) {
      currentByHour.set(key, (currentByHour.get(key) || 0) + g.count);
    }
  }
  for (const [key, count] of currentByHour.entries()) {
    merged.set(key, count);
  }

  let current24h = 0;
  let previous24h = 0;
  const hourly_history: TimelineItem[] = [];
  const sortedKeys = Array.from(merged.keys()).sort((a, b) => a - b);

  for (const key of sortedKeys) {
    const count = merged.get(key) || 0;
    if (key >= splitKey) {
      current24h += count;
    } else {
      previous24h += count;
    }
    hourly_history.push({
      hour: new Date(key * HOUR_MS).toISOString(),
      count,
    });
  }

  const ratio = previous24h > 0 ? Number((current24h / previous24h).toFixed(2)) : 1.0;
  let level: BaselineLevel = 'normal';
  if (ratio >= 3.0) level = 'critical';
  else if (ratio >= 2.0) level = 'spike';
  else if (ratio >= 1.5) level = 'elevated';

  return {
    current_24h: current24h,
    previous_24h: previous24h,
    ratio,
    level,
    hourly_history,
  };
}

// TD #42 (Phase 2.5): Probe-traffic ASN aggregation (k >= 5, 0 IPs).
export function aggregateAttackerNetworks(
  account: GraphQLAccountData,
  minK = 5,
): AttackerNetworkItem[] {
  const byAsn = account.byAsn ?? [];
  const merged = new Map<number, { description: string; count: number }>();

  for (const g of byAsn) {
    const status = g.dimensions.edgeResponseStatus;
    if (!PROBE_ATTACK_STATUSES.has(status)) continue;

    const asn = Number(g.dimensions.clientAsn);
    if (!Number.isInteger(asn) || asn <= 0) continue;

    const rawDesc = g.dimensions.clientASNDescription ?? '';
    const desc = sanitizeTelemetryText(rawDesc, MAX_ASN_DESC_LEN).trim() || 'UNKNOWN';
    const existing = merged.get(asn);
    if (existing) {
      existing.count += g.count;
      if (existing.description === 'UNKNOWN' && desc !== 'UNKNOWN') {
        existing.description = desc;
      }
    } else {
      merged.set(asn, { description: desc, count: g.count });
    }
  }

  return Array.from(merged.entries())
    .filter(([, entry]) => entry.count >= minK)
    .map(([asn, entry]) => ({ asn, description: entry.description, count: entry.count }))
    .sort((a, b) => b.count - a.count || a.asn - b.asn)
    .slice(0, 20);
}

// TD #42 (Phase 2.5): Separate Tor (T1) and Unknown (XX / null / Unknown) counters.
export function aggregateSpecialSources(
  account: GraphQLAccountData,
): SpecialSourcesBreakdown {
  const httpGroups = account.byStatusCountry ?? [];
  let torRequests = 0;
  let unknownGeo = 0;

  for (const g of httpGroups) {
    const raw = g.dimensions.clientCountryName;
    const cleaned = raw ? sanitizeTelemetryText(raw, MAX_COUNTRY_LEN) : '';
    if (cleaned === 'T1') {
      torRequests += g.count;
    } else if (!cleaned || cleaned === 'XX' || cleaned === UNKNOWN_COUNTRY) {
      unknownGeo += g.count;
    }
  }

  const by_code: GeoDataItem[] = [];
  if (torRequests > 0) by_code.push({ country: 'T1', count: torRequests });
  if (unknownGeo > 0) by_code.push({ country: 'XX', count: unknownGeo });
  by_code.sort((a, b) => b.count - a.count);

  return {
    tor_requests: torRequests,
    unknown_geo: unknownGeo,
    total: torRequests + unknownGeo,
    by_code,
  };
}