// Security Monitor — snapshot builder.
// Phase 1 (Pass 193): separates collection (cron -> KV) from serving (fetch -> KV).
// Contract v2 is additive on v1: all v1 keys preserved verbatim via aggregate().

import type {
  GraphQLAccountData,
  SnapshotMeta,
  SnapshotResponse,
  AggregateTrafficConfig,
  AuthEventInput,
} from './types';
import {
  aggregate,
  aggregateTraffic,
  aggregateProbes,
  aggregateErrors5xx,
  aggregateUaFamilies,
  aggregateAuth,
  computeBaseline,
  aggregateAttackerNetworks,
  aggregateSpecialSources,
} from './aggregate';

const SCHEMA_VERSION = '2.0' as const;

export interface BuildSnapshotOptions {
  windowStart: Date;
  windowEnd: Date;
  stale?: boolean;
  sampled?: boolean;
  quotaWarning?: boolean;
  // M-03 (v2): optional; unset => 	raffic omitted from SnapshotResponse.
  trafficConfig?: AggregateTrafficConfig;
  authEvents?: AuthEventInput[];
  previousSnapshot?: SnapshotResponse;
}

export function buildSnapshot(
  account: GraphQLAccountData,
  options: BuildSnapshotOptions,
): SnapshotResponse {
  const base = aggregate(account, options.windowEnd);
  const meta: SnapshotMeta = {
    generated_at: options.windowEnd.toISOString(),
    window_start: options.windowStart.toISOString(),
    window_end: options.windowEnd.toISOString(),
    stale: options.stale ?? false,
    sampled: options.sampled ?? false,
    quota_warning: options.quotaWarning ?? false,
  };
  const result: SnapshotResponse = {
    ...base,
    schema_version: SCHEMA_VERSION,
    meta,
  };
  if (options.trafficConfig) {
    result.traffic = aggregateTraffic(account, options.trafficConfig);
  }
  // M-04 (v2): probes always built (no config needed). Additive.
  result.probes = aggregateProbes(account);
  result.errors_5xx = aggregateErrors5xx(account);
  result.ua_families = aggregateUaFamilies(account);
  result.auth = aggregateAuth(options.authEvents ?? [], options.windowEnd);
  result.baseline = computeBaseline(account, options.windowEnd, options.previousSnapshot?.baseline);
  result.attacker_networks = aggregateAttackerNetworks(account);
  result.special_sources = aggregateSpecialSources(account);
  return result;
}

// Preserves generated_at (data collection time) — only sets stale flag.
// Used by scheduled() when GraphQL refresh fails but a previous snapshot exists.
export function markStale(prev: SnapshotResponse): SnapshotResponse {
  return {
    ...prev,
    meta: { ...prev.meta, stale: true },
  };
}
