using SOCPlatform.Core.Enums;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Pluggable adapter contract for an external threat-intelligence feed.
/// Implementations: AbuseIPDB, VirusTotal, URLhaus, ThreatFox, MISP, …
/// Each adapter handles one or more IndicatorTypes via SupportsType().
/// </summary>
public interface IThreatFeedAdapter
{
    /// <summary>Display name of the source feed (matches ThreatIntelIndicator.Source).</summary>
    string Name { get; }

    /// <summary>True if this adapter can look up the given indicator type.</summary>
    bool SupportsType(IndicatorType type);

    /// <summary>
    /// Look up a single indicator. Returns null when the value is unknown to the feed.
    /// Returns a populated <see cref="ThreatFeedHit"/> when malicious / suspicious.
    /// Should NOT throw on transport errors — log and return null instead.
    /// </summary>
    Task<ThreatFeedHit?> LookupAsync(IndicatorType type, string value, CancellationToken ct = default);

    /// <summary>
    /// Stream the full bulk feed (called by the sync job, typically every 6h).
    /// Implementations that don't support bulk export return an empty sequence.
    /// </summary>
    IAsyncEnumerable<ThreatFeedHit> StreamBulkAsync(CancellationToken ct = default);
}

/// <summary>
/// One indicator returned by a threat-feed adapter. The value is normalized
/// (lowercase, trimmed) by the adapter before returning.
/// </summary>
public sealed record ThreatFeedHit(
    IndicatorType IndicatorType,
    string Value,
    string Source,
    int ConfidenceScore,         // 0–100
    string ThreatType,           // "Malware" / "C2" / "Phishing" / "Botnet" / …
    string ThreatLevel,          // "Critical" / "High" / "Medium" / "Low" / "Informational"
    string? Description = null,
    string? Tags = null,         // CSV
    string? GeoCountry = null,
    string? Asn = null,
    string? MitreTechniques = null,
    DateTime? FirstSeenAt = null,
    DateTime? ExpiresAt = null,
    IReadOnlyDictionary<string, object>? RawMetadata = null);
