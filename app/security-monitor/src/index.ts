export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    // Безопасный CORS
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

    // Добавляем clientCountryName в запрос
    const query = `
      query getSecurityStats($accountId: String!, $startTime: Time!) {
        viewer {
          accounts(filter: {accountTag: $accountId}) {
            workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: $startTime}) {
              sum { requests errors }
            }
            byStatusCountry: httpRequestsAdaptiveGroups(limit: 100, filter: {datetime_geq: $startTime}) {
              count
              dimensions {
                edgeResponseStatus
                clientCountryName
              }
            }
            byHour: httpRequestsAdaptiveGroups(limit: 24, filter: {datetime_geq: $startTime}, orderBy: [datetimeHour_ASC]) {
              count
              dimensions {
                datetimeHour
              }
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

      // Build 24-bucket hourly timeline (oldest -> newest), zero-filled.
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
      const threatsByCountry: Record<string, number> = {};

      // Считаем блокировки и собираем статистику по странам
      httpGroups.forEach((group: any) => {
        const status = group.dimensions.edgeResponseStatus;
        const country = group.dimensions.clientCountryName || "Unknown";
        
        if (status === 403) blocked403 += group.count;
        if (status === 429) blocked429 += group.count;

        // Суммируем запросы по странам для глобуса
        if (country !== "Unknown") {
          threatsByCountry[country] = (threatsByCountry[country] || 0) + group.count;
        }
      });

      // Превращаем объект в массив для удобства React
      const countryData = Object.keys(threatsByCountry).map(key => ({
        country: key,
        count: threatsByCountry[key]
      })).sort((a, b) => b.count - a.count); // Сортируем: где больше атак — выше в списке

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
        timeline: timeline
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