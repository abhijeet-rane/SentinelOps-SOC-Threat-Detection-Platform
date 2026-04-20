using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Resilience;

namespace SOCPlatform.API.HealthChecks;

/// <summary>
/// Pings VirusTotal with the API users/me endpoint (cheapest call). Same Healthy/Degraded/Unhealthy semantics.
/// </summary>
public sealed class VirusTotalHealthCheck : IHealthCheck
{
    private readonly IHttpClientFactory _factory;
    private readonly ThreatIntelOptions _options;

    public VirusTotalHealthCheck(IHttpClientFactory factory, IOptions<ThreatIntelOptions> options)
    {
        _factory = factory;
        _options = options.Value;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.VirusTotal.ApiKey))
            return HealthCheckResult.Degraded("VirusTotal API key not configured");

        try
        {
            var client = _factory.CreateClient(PolicyRegistry.VirusTotalClient);
            var resp = await client.GetAsync("users/current", cancellationToken);
            return resp.IsSuccessStatusCode
                ? HealthCheckResult.Healthy("VirusTotal reachable")
                : HealthCheckResult.Degraded($"VirusTotal returned {(int)resp.StatusCode}");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("VirusTotal unreachable", ex);
        }
    }
}
