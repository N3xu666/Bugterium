// Security Monitor — snapshot builder.
// Phase 1 (Pass 193): separates collection (cron -> KV) from serving (fetch -> KV).
// Contract v2 is additive on v1: all v1 keys preserved verbatim via aggregate().

import type { GraphQLAccountData, SnapshotMeta, SnapshotResponse } from './types';
import { aggregate } from './aggregate';

const SCHEMA_VERSION = '2.0' as const;

export interface BuildSnapshotOptions {
  windowStart: Date;
  windowEnd: Date;
  stale?: boolean;
  sampled?: boolean;
  quotaWarning?: boolean;
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
  return {
    ...base,
    schema_version: SCHEMA_VERSION,
    meta,
  };
}

// Preserves generated_at (data collection time) — only sets stale flag.
// Used by scheduled() when GraphQL refresh fails but a previous snapshot exists.
export function markStale(prev: SnapshotResponse): SnapshotResponse {
  return {
    ...prev,
    meta: { ...prev.meta, stale: true },
  };
}
