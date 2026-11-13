// Security Monitor — Cloudflare GraphQL client.
// Phase 1 (Pass 193): ONLY scheduled() calls this. fetch() NEVER touches GraphQL.
// Contract: throws on any error. Caller (scheduled) decides stale/KV fallback.

import type { Env, GraphQLAccountData, GraphQLAsnGroup, GraphQLResponse } from './types';

const GRAPHQL_ENDPOINT = 'https://api.cloudflare.com/client/v4/graphql';

// Copied verbatim from pre-Phase-1 src/index.ts lines 19..49.
// DO NOT EDIT without re-running test/fixtures/graphql-response.json against real API.
const GRAPHQL_QUERY = `
  query getSecurityStats($accountId: String!, $startTime: Time!) {
    viewer {
      accounts(filter: {accountTag: $accountId}) {
        workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: $startTime}) {
          sum { requests errors }
        }
        byStatusCountry: httpRequestsAdaptiveGroups(limit: 100, filter: {datetime_geq: $startTime}, orderBy: [count_DESC]) {
          count
          dimensions { edgeResponseStatus clientCountryName }
        }
        byHour: httpRequestsAdaptiveGroups(limit: 24, filter: {datetime_geq: $startTime}, orderBy: [datetimeHour_ASC]) {
          count
          dimensions { datetimeHour }
        }
        byPath: httpRequestsAdaptiveGroups(limit: 500, filter: {datetime_geq: $startTime}, orderBy: [count_DESC]) {
          count
          dimensions { clientRequestPath }
        }
        byPathCountry: httpRequestsAdaptiveGroups(limit: 1000, filter: {datetime_geq: $startTime}, orderBy: [count_DESC]) {
          count
          dimensions { clientRequestPath clientCountryName }
        }
        byUserAgent: httpRequestsAdaptiveGroups(limit: 50, filter: {datetime_geq: $startTime}, orderBy: [count_DESC]) {
          count
          dimensions { userAgent edgeResponseStatus }
        }
        byHost: httpRequestsAdaptiveGroups(limit: 100, filter: {datetime_geq: $startTime}, orderBy: [count_DESC]) {
          count
          dimensions { clientRequestHTTPHost }
        }
      }
    }
  }
`;

export async function fetchGraphQLAccount(
  env: Env,
  startTime: string,
): Promise<GraphQLAccountData> {
  const gqlResponse = await fetch(GRAPHQL_ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.CF_API_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      query: GRAPHQL_QUERY,
      variables: { accountId: env.CF_ACCOUNT_ID, startTime },
    }),
  });

  if (!gqlResponse.ok) {
    throw new Error(`graphql_http_${gqlResponse.status}`);
  }

  const body = (await gqlResponse.json()) as GraphQLResponse;

  if (body.errors && body.errors.length > 0) {
    throw new Error(`graphql_errors_${body.errors.length}`);
  }

  const account = body.data?.viewer?.accounts?.[0];
  if (!account) {
    throw new Error('graphql_missing_data');
  }

  return account;
}

// TD #42 (Phase 2.5): Isolated secondary query for probe-traffic ASN groups.
// Kept separate from GRAPHQL_QUERY so Cloudflare plan/schema limits on clientAsn
// never break the primary snapshot cron.
const GRAPHQL_ASN_QUERY = `
  query getSecurityAsn($accountId: String!, $startTime: Time!) {
    viewer {
      accounts(filter: {accountTag: $accountId}) {
        byAsn: httpRequestsAdaptiveGroups(
          limit: 100
          filter: {datetime_geq: $startTime, edgeResponseStatus_in: [403, 404, 429]}
          orderBy: [count_DESC]
        ) {
          count
          dimensions {
            clientAsn
            clientASNDescription
            edgeResponseStatus
          }
        }
      }
    }
  }
`;

export async function fetchGraphQLAsn(
  env: Env,
  startTime: string,
): Promise<GraphQLAsnGroup[]> {
  const gqlResponse = await fetch(GRAPHQL_ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.CF_API_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      query: GRAPHQL_ASN_QUERY,
      variables: { accountId: env.CF_ACCOUNT_ID, startTime },
    }),
  });

  if (!gqlResponse.ok) {
    throw new Error(`graphql_asn_http_${gqlResponse.status}`);
  }

  const body = (await gqlResponse.json()) as GraphQLResponse;
  if (body.errors && body.errors.length > 0) {
    throw new Error(`graphql_asn_errors_${body.errors.length}`);
  }

  return body.data?.viewer?.accounts?.[0]?.byAsn ?? [];
}
