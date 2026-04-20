using System.Globalization;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;

namespace SOCPlatform.Infrastructure.ThreatIntel.Adapters;

/// <summary>
/// abuse.ch URLhaus (https://urlhaus.abuse.ch/) adapter.
/// No API key needed. Bulk-only: streams the recent CSV feed of malicious URLs.
/// Per-indicator lookups would need their per-URL API; we don't run those
/// because the bulk feed already has every recent malicious URL.
/// </summary>
public sealed class UrlhausAdapter : IThreatFeedAdapter
{
    public const string FeedUrl = "https://urlhaus.abuse.ch/downloads/csv_recent/";
    private static readonly HttpClient SharedClient = new() { Timeout = TimeSpan.FromSeconds(60) };

    public string Name => "URLhaus";

    private readonly ILogger<UrlhausAdapter> _logger;

    public UrlhausAdapter(ILogger<UrlhausAdapter> logger) => _logger = logger;

    public bool SupportsType(IndicatorType type) => type is IndicatorType.Url or IndicatorType.Domain;

    /// <summary>Per-indicator lookups go through the bulk feed during sync, not on-demand.</summary>
    public Task<ThreatFeedHit?> LookupAsync(IndicatorType type, string value, CancellationToken ct = default)
        => Task.FromResult<ThreatFeedHit?>(null);

    public async IAsyncEnumerable<ThreatFeedHit> StreamBulkAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        // Open the response + stream + reader and KEEP them alive for the whole
        // enumeration. The previous version disposed the HttpResponseMessage
        // before reading, which closed the stream.
        HttpResponseMessage? resp = null;
        Stream? stream = null;
        StreamReader? reader = null;
        try
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, FeedUrl);
                req.Headers.UserAgent.ParseAdd("SentinelOps-SOC/1.0 (+https://github.com)");
                resp = await SharedClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                resp.EnsureSuccessStatusCode();
                stream = await resp.Content.ReadAsStreamAsync(ct);
                reader = new StreamReader(stream);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "URLhaus feed download failed");
                yield break;
            }

            int parsed = 0, skipped = 0;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(ct);
                if (line is null) break;
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;

            var fields = ParseCsvLine(line);
            if (fields.Length < 9) { skipped++; continue; }

            // URLhaus CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            var url = fields[2];
            var status = fields[3];
            var threat = fields[5];
            var tags = fields[6];

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) { skipped++; continue; }
            if (!DateTime.TryParse(fields[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var addedAt))
                addedAt = DateTime.UtcNow;

            var (level, confidence) = ClassifyStatus(status);

            // Emit one URL hit
            yield return new ThreatFeedHit(
                IndicatorType: IndicatorType.Url,
                Value: url.ToLowerInvariant(),
                Source: Name,
                ConfidenceScore: confidence,
                ThreatType: NormalizeThreat(threat),
                ThreatLevel: level,
                Description: $"URLhaus #{fields[0]} · status={status} · reporter={fields[8]}",
                Tags: tags,
                FirstSeenAt: addedAt,
                ExpiresAt: addedAt.AddDays(30));

            // ALSO emit the host as a domain hit so DNS-level matches fire
            yield return new ThreatFeedHit(
                IndicatorType: IndicatorType.Domain,
                Value: uri.Host.ToLowerInvariant(),
                Source: Name,
                ConfidenceScore: confidence,
                ThreatType: NormalizeThreat(threat),
                ThreatLevel: level,
                Description: $"URLhaus host of #{fields[0]}",
                Tags: tags,
                FirstSeenAt: addedAt,
                ExpiresAt: addedAt.AddDays(30));

                parsed++;
            }

            _logger.LogInformation("URLhaus bulk parse: {Parsed} indicators emitted, {Skipped} skipped", parsed * 2, skipped);
        }
        finally
        {
            reader?.Dispose();
            if (stream is not null) await stream.DisposeAsync();
            resp?.Dispose();
        }
    }

    private static (string level, int confidence) ClassifyStatus(string status) => status?.ToLowerInvariant() switch
    {
        "online"  => ("Critical", 95),
        "offline" => ("High",     75),
        _         => ("Medium",   60)
    };

    private static string NormalizeThreat(string threat) => threat?.ToLowerInvariant() switch
    {
        "malware_download" => "Malware Distribution",
        "phishing"         => "Phishing",
        "exploit_kit"      => "Exploit Kit",
        "ransomware"       => "Ransomware",
        _ => string.IsNullOrWhiteSpace(threat) ? "Malicious URL" : threat
    };

    /// <summary>Tiny CSV parser that respects quoted fields. URLhaus rows are simple — no embedded newlines.</summary>
    private static string[] ParseCsvLine(string line)
    {
        var result = new List<string>(9);
        var sb = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (var c in line)
        {
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (c == ',' && !inQuotes) { result.Add(sb.ToString().Trim()); sb.Clear(); continue; }
            sb.Append(c);
        }
        result.Add(sb.ToString().Trim());
        return result.ToArray();
    }
}
