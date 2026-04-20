using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Resilience;

namespace SOCPlatform.API.HealthChecks;

/// <summary>
/// Pings AbuseIPDB with a low-cost lookup of 8.8.8.8. Returns Degraded if missing key,
/// Unhealthy on transport error, Healthy otherwise.
/// </summary>
public sealed class AbuseIpDbHealthCheck : IHealthCheck
{
    private readonly IHttpClientFactory _factory;
    private readonly ThreatIntelOptions _options;

    public AbuseIpDbHealthCheck(IHttpClientFactory factory, IOptions<ThreatIntelOptions> options)
    {
        _factory = factory;
        _options = options.Value;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.AbuseIpDb.ApiKey))
            return HealthCheckResult.Degraded("AbuseIPDB API key not configured");

        try
        {
            var client = _factory.CreateClient(PolicyRegistry.AbuseIpDbClient);
            var resp = await client.GetAsync("check?ipAddress=8.8.8.8&maxAgeInDays=1", cancellationToken);
            return resp.IsSuccessStatusCode
                ? HealthCheckResult.Healthy("AbuseIPDB reachable")
                : HealthCheckResult.Degraded($"AbuseIPDB returned {(int)resp.StatusCode}");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("AbuseIPDB unreachable", ex);
        }
    }
}
