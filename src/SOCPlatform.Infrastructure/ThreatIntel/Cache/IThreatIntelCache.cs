using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;

namespace SOCPlatform.Infrastructure.ThreatIntel.Cache;

/// <summary>
/// Caches per-(adapter, type, value) lookup results. Two outcomes are cached:
///   • A hit (the adapter said malicious) — lets repeated probes skip the network
///   • A miss (adapter said unknown)        — equally important; stops an attacker
///     from triggering N enrichment hits for free per probe and burns the
///     AbuseIPDB free-tier 1k/day budget unnecessarily
/// </summary>
public interface IThreatIntelCache
{
    /// <summary>
    /// Fetch a previously-cached lookup. Returns:
    ///   • (true,  hit)  when a malicious result was cached
    ///   • (true,  null) when a "definitely not malicious" miss was cached
    ///   • (false, null) when nothing is cached
    /// </summary>
    Task<(bool Cached, ThreatFeedHit? Hit)> TryGetAsync(
        string adapter, IndicatorType type, string value, CancellationToken ct = default);

    /// <summary>Cache a hit (malicious result).</summary>
    Task SetHitAsync(
        string adapter, IndicatorType type, string value, ThreatFeedHit hit, CancellationToken ct = default);

    /// <summary>Cache a miss (unknown / clean).</summary>
    Task SetMissAsync(
        string adapter, IndicatorType type, string value, CancellationToken ct = default);
}
