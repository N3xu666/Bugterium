// Security Monitor — shared types.
// Contract: JSON shape is IDENTICAL to the pre-refactor response.
// Frontend invariants (F-01..F-05):
//   F-01 geo_data: [{country, count}] — used by useMemo -> onPointClick chain
//   F-02 attacks_by_country: [{country, count}] — SUSPICIOUS mode
//   F-03 path_data.correlations + user_agent_data — filters
//   F-04 country !== "Unknown" filter — preserved
//   F-05 new arrays per update — preserved (fresh response per request)
// Any change here is a frontend breaking change.

// Worker environment bindings.
export interface Env {
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  MONITOR_KV: KVNamespace;
  DB?: D1Database;
  // M-03 (v2): optional host config for traffic breakdown.
  // Unset => 	raffic omitted from SnapshotResponse.
  SITE_HOST?: string;
  MONITOR_HOST?: string;
  BFF_HOST?: string;
}

// --- Response contract v1 ---

export interface SecurityMetrics {
  worker_requests_24h: number;
  worker_errors_24h: number;
  blocked_403: number;
  blocked_429: number;
  client_errors_4xx: number;
  server_errors_5xx: number;
  health_percent: string;
}

export interface StatusBreakdownItem {
  code: number;
  count: number;
}

export interface GeoDataItem {
  country: string;
  count: number;
}

export interface TimelineItem {
  hour: string;
  count: number;
}

export interface PathItem {
  path: string;
  count: number;
}

export interface PathData {
  attacks: PathItem[];
  benign: PathItem[];
  correlations: Record<string, Record<string, number>>;
}

export interface UserAgentItem {
  ua: string;
  count: number;
}

export interface UserAgentData {
  traffic: UserAgentItem[];
  attacks: UserAgentItem[];
}

// --- v2 additive types (M-03: traffic host split) ---

export interface GraphQLHostGroup {
  count: number;
  dimensions: {
    clientRequestHTTPHost: string | null;
  };
}

export interface HostTrafficItem {
  host: string;
  count: number;
}

export interface TrafficBreakdown {
  site_requests: number;
  own_polling: number;
  bff_requests: number;
  other_http: number;
  // @deprecated Pass 196 (M-03 tail): cannot compute reliably - Workers invocations
  // and HTTP requests (incl. Pages static) are DIFFERENT datasets. Always 0.
  // Use total_workers for the raw Worker invocation count. Kept for v2 contract compat.
  cron_invocations: number;
  // Pass 196: raw Worker invocations from workersInvocationsAdaptive (cron + fetch combined).
  total_workers: number;
  hosts: HostTrafficItem[];
  human_est: number;
  bot_est: number;
  scanner_est: number;
}

// M-04 (v2): Probe outcome split (reached / not_found / blocked / error).
export interface ProbesOutcome {
  reached: number;
  not_found: number;
  blocked: number;
  error: number;
}

// M-06 (v2): Probe family classification by path signature.
export interface ProbesFamily {
  family: string;
  count: number;
}
export interface ProbesBreakdown {
  total: number;
  by_outcome: ProbesOutcome;
  top_paths: PathItem[];
  families: ProbesFamily[];
}
export interface AggregateTrafficConfig {
  siteHost?: string;
  monitorHost?: string;
  bffHost?: string;
}

// P2.4 (v2): User-Agent family classification (no raw UA).
export type UaFamilyName = 'browser' | 'automation' | 'scanner' | 'crawler' | 'unknown';

export interface UaFamilyItem {
  family: UaFamilyName;
  count: number;
}

// P2.5 & M-05 (v2): 5xx error breakdown separating platform (502/503/504) vs app (500/501/505).
export interface Error5xxCodeItem {
  code: number;
  count: number;
  classification: 'platform' | 'app';
}

export interface Errors5xxBreakdown {
  total: number;
  platform_5xx: number;
  app_5xx: number;
  by_code: Error5xxCodeItem[];
  by_cache: Array<{ status: string; count: number }>;
  by_origin_status: Array<{ code: number; count: number }>;
}

// P1.1 (v2): BFF auth_events hourly tracking (0 PII, counts only).
export interface AuthEventInput {
  hour_epoch: number;
  event: string;
  count: number;
}

export interface AuthHourItem {
  hour: string;
  login_success: number;
  login_fail: number;
  forbidden: number;
  logout: number;
}

export interface AuthBreakdown {
  totals: {
    login_success: number;
    login_fail: number;
    forbidden: number;
    logout: number;
  };
  by_hour: AuthHourItem[];
}

// P1.1 (v2): Rolling 48h KV baseline (0 extra KV writes).
export type BaselineLevel = 'normal' | 'elevated' | 'spike' | 'critical';

export interface BaselineBreakdown {
  current_24h: number;
  previous_24h: number;
  ratio: number;
  level: BaselineLevel;
  hourly_history: TimelineItem[];
}

// TD #42 (Phase 2.5): Probe-traffic ASN aggregation (k >= 5, 0 IPs) & T1/XX special sources.
export interface GraphQLAsnGroup {
  count: number;
  dimensions: {
    clientAsn: number | string | null;
    clientASNDescription: string | null;
    edgeResponseStatus: number;
  };
}

export interface AttackerNetworkItem {
  asn: number;
  description: string;
  count: number;
}

export interface SpecialSourcesBreakdown {
  tor_requests: number;
  unknown_geo: number;
  total: number;
  by_code: GeoDataItem[];
}

export interface SnapshotMeta {
  generated_at: string;
  window_start: string;
  window_end: string;
  stale: boolean;
  sampled: boolean;
  quota_warning: boolean;
}

export interface SnapshotResponse extends MonitorResponse {
  schema_version: '2.0';
  meta: SnapshotMeta;
  traffic?: TrafficBreakdown;  // M-03: v2 additive, undefined = not computed
  probes?: ProbesBreakdown;  // M-04: v2 additive, undefined = not computed
  errors_5xx?: Errors5xxBreakdown;
  auth?: AuthBreakdown;
  baseline?: BaselineBreakdown;
  ua_families?: UaFamilyItem[];
  attacker_networks?: AttackerNetworkItem[];
  special_sources?: SpecialSourcesBreakdown;
}

export interface MonitorResponse {
  status: 'ok';
  timestamp: string;
  security_metrics: SecurityMetrics;
  status_breakdown: StatusBreakdownItem[];
  geo_data: GeoDataItem[];
  attacks_by_country: GeoDataItem[];
  timeline: TimelineItem[];
  path_data: PathData;
  user_agent_data: UserAgentData;
}

// Error response — generic only (M-09: no details, no error.message).
export interface MonitorErrorResponse {
  status: 'error';
  code: string;
}

// --- Cloudflare GraphQL response shapes (only fields we use) ---

export interface GraphQLInvocationSum {
  requests: number;
  errors: number;
}

export interface GraphQLStatusCountryGroup {
  count: number;
  dimensions: {
    edgeResponseStatus: number;
    clientCountryName: string | null;
  };
}

export interface GraphQLHourGroup {
  count: number;
  dimensions: {
    datetimeHour: string;
  };
}

export interface GraphQLPathGroup {
  count: number;
  dimensions: {
    clientRequestPath: string | null;
  };
}

export interface GraphQLPathCountryGroup {
  count: number;
  dimensions: {
    clientRequestPath: string | null;
    clientCountryName: string | null;
  };
}

export interface GraphQLUserAgentGroup {
  count: number;
  dimensions: {
    userAgent: string | null;
    edgeResponseStatus: number;
  };
}

export interface GraphQLAccountData {
  workersInvocationsAdaptive: Array<{ sum: GraphQLInvocationSum }>;
  byStatusCountry: GraphQLStatusCountryGroup[];
  byHour: GraphQLHourGroup[];
  byPath: GraphQLPathGroup[];
  byPathCountry: GraphQLPathCountryGroup[];
  byUserAgent: GraphQLUserAgentGroup[];
  byHost?: GraphQLHostGroup[];  // M-03: v2 additive, undefined = not queried
  byAsn?: GraphQLAsnGroup[];    // TD #42: optional ASN probe slice, undefined = unavailable
}

export interface GraphQLError {
  message: string;
}

export interface GraphQLResponse {
  data?: {
    viewer: {
      accounts: GraphQLAccountData[];
    };
  };
  errors?: GraphQLError[];
}