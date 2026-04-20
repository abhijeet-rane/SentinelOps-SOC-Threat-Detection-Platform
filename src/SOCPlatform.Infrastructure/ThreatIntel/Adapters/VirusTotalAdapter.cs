using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Resilience;

namespace SOCPlatform.Infrastructure.ThreatIntel.Adapters;

/// <summary>
/// VirusTotal v3 adapter (https://docs.virustotal.com/reference/overview).
/// Supports file hash, URL, domain, IP. Free public tier: 4 req/min, 500/day.
/// Maps the AV verdict ratio (malicious/total) to ConfidenceScore.
/// </summary>
public sealed class VirusTotalAdapter : IThreatFeedAdapter
{
    public string Name => "VirusTotal";

    private readonly IHttpClientFactory _httpFactory;
    private readonly ThreatIntelOptions _options;
    private readonly ILogger<VirusTotalAdapter> _logger;

    public VirusTotalAdapter(
        IHttpClientFactory httpFactory,
        IOptions<ThreatIntelOptions> options,
        ILogger<VirusTotalAdapter> logger)
    {
        _httpFactory = httpFactory;
        _options = options.Value;
        _logger = logger;
    }

    public bool SupportsType(IndicatorType type) => type is
        IndicatorType.FileHash or IndicatorType.Url or IndicatorType.Domain or IndicatorType.IpAddress;

    public async Task<ThreatFeedHit?> LookupAsync(IndicatorType type, string value, CancellationToken ct = default)
    {
        if (!SupportsType(type)) return null;
        if (string.IsNullOrWhiteSpace(_options.VirusTotal.ApiKey))
        {
            _logger.LogDebug("VirusTotal skipped: API key not configured");
            return null;
        }

        var endpoint = type switch
        {
            IndicatorType.FileHash  => $"files/{Uri.EscapeDataString(value)}",
            IndicatorType.IpAddress => $"ip_addresses/{Uri.EscapeDataString(value)}",
            IndicatorType.Domain    => $"domains/{Uri.EscapeDataString(value)}",
            IndicatorType.Url       => $"urls/{ToVtUrlId(value)}",
            _ => null
        };
        if (endpoint is null) return null;

        try
        {
            var client = _httpFactory.CreateClient(PolicyRegistry.VirusTotalClient);
            using var resp = await client.GetAsync(endpoint, ct);

            // 404 == VT has never seen the indicator → clean / unknown
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("VirusTotal returned {Status} for {Type} {Value}", resp.StatusCode, type, value);
                return null;
            }

            using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);

            if (!doc.RootElement.TryGetProperty("data", out var data)) return null;
            if (!data.TryGetProperty("attributes", out var attrs)) return null;
            if (!attrs.TryGetProperty("last_analysis_stats", out var statsEl)) return null;

            var malicious  = statsEl.TryGetProperty("malicious",  out var m) ? m.GetInt32() : 0;
            var suspicious = statsEl.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
            var harmless   = statsEl.TryGetProperty("harmless",   out var h) ? h.GetInt32() : 0;
            var undetected = statsEl.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0;

            var totalAv = malicious + suspicious + harmless + undetected;
            if (totalAv == 0 || (malicious + suspicious) == 0) return null; // clean

            var ratio = (double)(malicious + suspicious) / totalAv;
            var confidence = (int)Math.Round(ratio * 100);

            string? threatLabel = null;
            if (attrs.TryGetProperty("popular_threat_classification", out var clsEl) &&
                clsEl.TryGetProperty("suggested_threat_label", out var lblEl))
                threatLabel = lblEl.GetString();

            var tags = attrs.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array
                ? string.Join(",", tagsEl.EnumerateArray().Select(t => t.GetString()).Where(t => t is not null))
                : null;
            var country  = attrs.TryGetProperty("country",  out var cEl)  ? cEl.GetString()  : null;
            var asOwner  = attrs.TryGetProperty("as_owner", out var aoEl) ? aoEl.GetString() : null;
            var firstSub = attrs.TryGetProperty("first_submission_date", out var fsEl) && fsEl.ValueKind == JsonValueKind.Number
                ? DateTimeOffset.FromUnixTimeSeconds(fsEl.GetInt64()).UtcDateTime
                : (DateTime?)null;

            var (level, threatType) = Classify(ratio, threatLabel, type);

            return new ThreatFeedHit(
                IndicatorType: type,
                Value: value.Trim().ToLowerInvariant(),
                Source: Name,
                ConfidenceScore: confidence,
                ThreatType: threatType,
                ThreatLevel: level,
                Description: $"VirusTotal: {malicious}/{totalAv} engines flagged malicious ({suspicious} suspicious)",
                Tags: tags,
                GeoCountry: country,
                Asn: asOwner,
                FirstSeenAt: firstSub,
                RawMetadata: new Dictionary<string, object>
                {
                    ["malicious"] = malicious,
                    ["suspicious"] = suspicious,
                    ["harmless"] = harmless,
                    ["undetected"] = undetected,
                });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "VirusTotal lookup failed for {Type} {Value}", type, value);
            return null;
        }
    }

    /// <summary>VirusTotal bulk feeds require an enterprise license — empty for free tier.</summary>
    public async IAsyncEnumerable<ThreatFeedHit> StreamBulkAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        await Task.CompletedTask;
        yield break;
    }

    /// <summary>
    /// VT URL identifier = url-safe base64 of the URL with no padding.
    /// </summary>
    private static string ToVtUrlId(string url)
    {
        var bytes = Encoding.UTF8.GetBytes(url);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static (string level, string threatType) Classify(double ratio, string? threatLabel, IndicatorType type)
    {
        var level = ratio switch
        {
            >= 0.40 => "Critical",
            >= 0.20 => "High",
            >= 0.05 => "Medium",
            _       => "Low"
        };

        var threatType = !string.IsNullOrWhiteSpace(threatLabel) ? threatLabel : type switch
        {
            IndicatorType.FileHash  => "Malware",
            IndicatorType.Url       => "Malicious URL",
            IndicatorType.Domain    => "Malicious Domain",
            IndicatorType.IpAddress => "Malicious IP",
            _ => "Suspicious"
        };

        return (level, threatType);
    }
}
