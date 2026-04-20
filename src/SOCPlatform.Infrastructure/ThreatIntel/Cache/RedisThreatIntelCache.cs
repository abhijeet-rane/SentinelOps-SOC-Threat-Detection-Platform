using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;

namespace SOCPlatform.Infrastructure.ThreatIntel.Cache;

/// <summary>
/// Redis-backed implementation. Hits + misses get the same TTL
/// (<see cref="ThreatIntelOptions.CacheTtlSeconds"/>, default 1h).
/// </summary>
public sealed class RedisThreatIntelCache : IThreatIntelCache
{
    private const string MissSentinel = "__miss__";

    private readonly IDistributedCache _cache;
    private readonly TimeSpan _ttl;

    public RedisThreatIntelCache(IDistributedCache cache, IOptions<ThreatIntelOptions> options)
    {
        _cache = cache;
        _ttl = TimeSpan.FromSeconds(Math.Max(60, options.Value.CacheTtlSeconds));
    }

    public async Task<(bool Cached, ThreatFeedHit? Hit)> TryGetAsync(
        string adapter, IndicatorType type, string value, CancellationToken ct = default)
    {
        var raw = await _cache.GetStringAsync(Key(adapter, type, value), ct);
        if (raw is null) return (false, null);
        if (raw == MissSentinel) return (true, null);

        try
        {
            var hit = JsonSerializer.Deserialize<ThreatFeedHit>(raw);
            return (true, hit);
        }
        catch
        {
            // Cached value got corrupted by a schema change — treat as miss
            return (false, null);
        }
    }

    public Task SetHitAsync(string adapter, IndicatorType type, string value, ThreatFeedHit hit, CancellationToken ct = default) =>
        _cache.SetStringAsync(
            Key(adapter, type, value),
            JsonSerializer.Serialize(hit),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = _ttl },
            ct);

    public Task SetMissAsync(string adapter, IndicatorType type, string value, CancellationToken ct = default) =>
        _cache.SetStringAsync(
            Key(adapter, type, value),
            MissSentinel,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = _ttl },
            ct);

    private static string Key(string adapter, IndicatorType type, string value)
        => $"ti:{adapter}:{type}:{value.Trim().ToLowerInvariant()}";
}
