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