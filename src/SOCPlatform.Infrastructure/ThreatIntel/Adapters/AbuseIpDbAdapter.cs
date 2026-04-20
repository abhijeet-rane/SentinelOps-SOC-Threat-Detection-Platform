using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Resilience;

namespace SOCPlatform.Infrastructure.ThreatIntel.Adapters;

/// <summary>
/// AbuseIPDB adapter (https://docs.abuseipdb.com/#check-endpoint).
/// IP reputation only. Free tier: 1000 lookups/day.
/// Score 0-100 from AbuseIPDB maps directly to ConfidenceScore.
/// </summary>
public sealed class AbuseIpDbAdapter : IThreatFeedAdapter
{
    public string Name => "AbuseIPDB";

    private readonly IHttpClientFactory _httpFactory;
    private readonly ThreatIntelOptions _options;
    private readonly ILogger<AbuseIpDbAdapter> _logger;

    public AbuseIpDbAdapter(
        IHttpClientFactory httpFactory,
        IOptions<ThreatIntelOptions> options,
        ILogger<AbuseIpDbAdapter> logger)
    {
        _httpFactory = httpFactory;
        _options = options.Value;
        _logger = logger;
    }

    public bool SupportsType(IndicatorType type) => type == IndicatorType.IpAddress;

    public async Task<ThreatFeedHit?> LookupAsync(IndicatorType type, string value, CancellationToken ct = default)
    {
        if (!SupportsType(type)) return null;
        if (string.IsNullOrWhiteSpace(_options.AbuseIpDb.ApiKey))
        {
            _logger.LogDebug("AbuseIPDB skipped: API key not configured");
            return null;
        }

        try
        {
            var client = _httpFactory.CreateClient(PolicyRegistry.AbuseIpDbClient);
            var url = $"check?ipAddress={Uri.EscapeDataString(value)}&maxAgeInDays={_options.AbuseIpDb.MaxConfidenceAge}&verbose";
            using var resp = await client.GetAsync(url, ct);

            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("AbuseIPDB returned {Status} for {Ip}", resp.StatusCode, value);
                return null;
            }

            using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            if (!doc.RootElement.TryGetProperty("data", out var data)) return null;

            var score = data.TryGetProperty("abuseConfidenceScore", out var s) ? s.GetInt32() : 0;
            if (score <= 0) return null; // Clean / unknown

            var country     = data.TryGetProperty("countryCode", out var c)      ? c.GetString() : null;
            var usageType   = data.TryGetProperty("usageType", out var u)        ? u.GetString() : null;
            var isp         = data.TryGetProperty("isp", out var i)              ? i.GetString() : null;
            var totalRep    = data.TryGetProperty("totalReports", out var tr)    ? tr.GetInt32() : 0;
            var distinctU   = data.TryGetProperty("numDistinctUsers", out var d) ? d.GetInt32() : 0;
            var isPublic    = data.TryGetProperty("isPublic", out var p)         && p.GetBoolean();
            var isWhitelist = data.TryGetProperty("isWhitelisted", out var w)    && w.ValueKind == JsonValueKind.True;
            var lastReport  = data.TryGetProperty("lastReportedAt", out var lr) && lr.ValueKind == JsonValueKind.String
                ? lr.GetDateTime() : (DateTime?)null;

            var (level, threatType) = ClassifyScore(score, usageType);

            return new ThreatFeedHit(
                IndicatorType: IndicatorType.IpAddress,
                Value: value.Trim().ToLowerInvariant(),
                Source: Name,
                ConfidenceScore: score,
                ThreatType: threatType,
                ThreatLevel: level,
                Description: $"AbuseIPDB confidence {score}% · {totalRep} reports · last {lastReport:O}",
                Tags: usageType,
                GeoCountry: country,
                Asn: isp,
                FirstSeenAt: null,
                ExpiresAt: DateTime.UtcNow.AddDays(_options.AbuseIpDb.MaxConfidenceAge),
                RawMetadata: new Dictionary<string, object>
                {
                    ["totalReports"] = totalRep,
                    ["numDistinctUsers"] = distinctU,
                    ["isPublic"] = isPublic,
                    ["isWhitelisted"] = isWhitelist
                });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "AbuseIPDB lookup failed for {Ip}", value);
            return null;
        }
    }

    /// <summary>AbuseIPDB has no bulk feed (free tier). Returns empty.</summary>
    public async IAsyncEnumerable<ThreatFeedHit> StreamBulkAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        await Task.CompletedTask;
        yield break;
    }

    private static (string level, string threatType) ClassifyScore(int score, string? usageType) => score switch
    {
        >= 90 => ("Critical", InferThreatType(usageType) ?? "Malicious IP"),
        >= 75 => ("High",     InferThreatType(usageType) ?? "Suspicious IP"),
        >= 50 => ("Medium",   InferThreatType(usageType) ?? "Suspicious IP"),
        _     => ("Low",      InferThreatType(usageType) ?? "Reported IP"),
    };

    private static string? InferThreatType(string? usageType) => usageType?.ToLowerInvariant() switch
    {
        var u when u?.Contains("data center") == true => "Bulletproof Hosting",
        var u when u?.Contains("commercial") == true => "Compromised Host",
        _ => null
    };
}
