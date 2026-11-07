export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    const origin = request.headers.get("Origin") || "";
    const allowedOrigins = ["https://bugterium.pages.dev", "http://localhost:3000"];
    const corsOrigin = allowedOrigins.includes(origin) ? origin : "https://bugterium.pages.dev";

    const corsHeaders = {
      "Access-Control-Allow-Origin": corsOrigin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const query = `
      query getSecurityStats($accountId: String!, $startTime: Time!) {
        viewer {
          accounts(filter: {accountTag: $accountId}) {
            workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: $startTime}) {
              sum { requests errors }
            }
            byStatusCountry: httpRequestsAdaptiveGroups(limit: 100, filter: {datetime_geq: $startTime}) {
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
            byPathCountry: httpRequestsAdaptiveGroups(limit: 1000, filter: {datetime_geq: $startTime}) {
              count
              dimensions { clientRequestPath clientCountryName }
            }
            byUserAgent: httpRequestsAdaptiveGroups(limit: 50, filter: {datetime_geq: $startTime}, orderBy: [count_DESC]) {
              count
              dimensions { userAgent edgeResponseStatus }
            }
          }
        }
      }
    `;

    try {
      const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + env.CF_API_TOKEN,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query: query,
          variables: { accountId: env.CF_ACCOUNT_ID, startTime: oneDayAgo }
        })
      });

      const data: any = await response.json();

      if (data.errors) {
        return new Response(JSON.stringify({ status: "error", details: data.errors }), {
          status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const accountData = data.data.viewer.accounts[0];
      const stats = accountData.workersInvocationsAdaptive;
      const httpGroups = accountData.byStatusCountry || [];
      const byHour = accountData.byHour || [];
      const byPath = accountData.byPath || [];
      const byPathCountry = accountData.byPathCountry || [];
      const byUserAgent = accountData.byUserAgent || [];

      const hourKey = (iso: string) => Math.floor(new Date(iso).getTime() / 3600000);
      const hourlyMap: Record<number, number> = {};
      byHour.forEach((group: any) => {
        const key = hourKey(group.dimensions.datetimeHour);
        hourlyMap[key] = (hourlyMap[key] || 0) + group.count;
      });
      const currentHourKey = Math.floor(Date.now() / 3600000);
      const timeline: { hour: string; count: number }[] = [];
      for (let i = 23; i >= 0; i--) {
        const key = currentHourKey - i;
        timeline.push({
          hour: new Date(key * 3600000).toISOString(),
          count: hourlyMap[key] || 0,
        });
      }

      let totalRequests = 0;
      let totalErrors = 0;
      if (stats && stats.length > 0) {
        stats.forEach((stat: any) => {
          totalRequests += stat.sum.requests || 0;
          totalErrors += stat.sum.errors || 0;
        });
      }

      let blocked403 = 0;
      let blocked429 = 0;
      const trafficByCountry: Record<string, number> = {};
      const attacksByCountry: Record<string, number> = {};

      httpGroups.forEach((group: any) => {
        const status = group.dimensions.edgeResponseStatus;
        const country = group.dimensions.clientCountryName || "Unknown";

        if (status === 403) blocked403 += group.count;
        if (status === 429) blocked429 += group.count;

        if (country !== "Unknown") {
          trafficByCountry[country] = (trafficByCountry[country] || 0) + group.count;
          
          // Считаем атакой: 403 (заблокировано), 404 (сканеры ищут несуществующее), 429 (превышение лимитов)
          if (status === 403 || status === 404 || status === 429) {
            attacksByCountry[country] = (attacksByCountry[country] || 0) + group.count;
          }
        }
      });

      const countryData = Object.keys(trafficByCountry).map(key => ({
        country: key, count: trafficByCountry[key]
      })).sort((a, b) => b.count - a.count);

      const attackCountryData = Object.keys(attacksByCountry).map(key => ({
        country: key, count: attacksByCountry[key]
      })).sort((a, b) => b.count - a.count);

      const attackRegex = /(\.env|wp-admin|wp-login|phpmyadmin|xmlrpc|config|\.git|\.aws|\.ssh|admin|login|shell|api\/v1)/i;
      const pathData = byPath.map((g: any) => ({ path: g.dimensions.clientRequestPath, count: g.count })).filter((x: any) => x.path);
      
      const attackPaths = pathData.filter((x: any) => attackRegex.test(x.path));
      const benignPaths = pathData.filter((x: any) => !attackRegex.test(x.path));

      const pathCountries: Record<string, Record<string, number>> = {};
      byPathCountry.forEach((g: any) => {
        const path = g.dimensions.clientRequestPath;
        const country = g.dimensions.clientCountryName;
        if (path && country && country !== "Unknown") {
          if (!pathCountries[path]) pathCountries[path] = {};
          pathCountries[path][country] = (pathCountries[path][country] || 0) + g.count;
        }
      });

      const uaTraffic: Record<string, number> = {};
      const uaAttacks: Record<string, number> = {};

      byUserAgent.forEach((g: any) => {
        const ua = g.dimensions.userAgent || "Unknown";
        const status = g.dimensions.edgeResponseStatus;
        if (status === 403 || status === 404 || status === 429) {
          uaAttacks[ua] = (uaAttacks[ua] || 0) + g.count;
        } else {
          uaTraffic[ua] = (uaTraffic[ua] || 0) + g.count;
        }
      });

      const mapAndSort = (obj: Record<string, number>) => Object.entries(obj)
        .map(([ua, count]) => ({ ua, count }))
        .sort((a, b) => b.count - a.count);

      const userAgentData = {
        traffic: mapAndSort(uaTraffic),
        attacks: mapAndSort(uaAttacks)
      };

      return new Response(JSON.stringify({
        status: "ok",
        timestamp: new Date().toISOString(),
        security_metrics: {
          worker_requests_24h: totalRequests,
          worker_errors_24h: totalErrors,
          blocked_403: blocked403,
          blocked_429: blocked429
        },
        geo_data: countryData,
        attacks_by_country: attackCountryData,
        timeline: timeline,
        path_data: {
          attacks: attackPaths,
          benign: benignPaths,
          correlations: pathCountries
        },
        user_agent_data: userAgentData
      }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });

    } catch (error: any) {
      return new Response(JSON.stringify({ status: "error", message: error.message }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  },
};