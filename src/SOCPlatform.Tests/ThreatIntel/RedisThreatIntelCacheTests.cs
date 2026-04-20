using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.ThreatIntel.Cache;

namespace SOCPlatform.Tests.ThreatIntel;

public class RedisThreatIntelCacheTests
{
    /// <summary>
    /// Test the cache against an in-memory IDistributedCache stand-in
    /// (MemoryDistributedCache) — same contract as Redis without the dependency.
    /// </summary>
    private static (RedisThreatIntelCache cache, IDistributedCache backing) Make(int ttlSeconds = 3600)
    {
        var backing = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var opts = Options.Create(new ThreatIntelOptions { CacheTtlSeconds = ttlSeconds });
        return (new RedisThreatIntelCache(backing, opts), backing);
    }

    [Fact]
    public async Task TryGet_Returns_Not_Cached_When_Empty()
    {
        var (cache, _) = Make();
        var (cached, hit) = await cache.TryGetAsync("AbuseIPDB", IndicatorType.IpAddress, "1.1.1.1");
        cached.Should().BeFalse();
        hit.Should().BeNull();
    }

    [Fact]
    public async Task SetMiss_Then_TryGet_Returns_Cached_Null()
    {
        var (cache, _) = Make();
        await cache.SetMissAsync("AbuseIPDB", IndicatorType.IpAddress, "1.1.1.1");
        var (cached, hit) = await cache.TryGetAsync("AbuseIPDB", IndicatorType.IpAddress, "1.1.1.1");
        cached.Should().BeTrue();
        hit.Should().BeNull("a cached miss is distinct from a cache miss");
    }

    [Fact]
    public async Task SetHit_Then_TryGet_Returns_Cached_Hit()
    {
        var (cache, _) = Make();
        var hit = new ThreatFeedHit(
            IndicatorType.IpAddress, "1.2.3.4", "AbuseIPDB", 90,
            "Botnet", "Critical", "Bad guy");

        await cache.SetHitAsync("AbuseIPDB", IndicatorType.IpAddress, "1.2.3.4", hit);
        var (cached, returned) = await cache.TryGetAsync("AbuseIPDB", IndicatorType.IpAddress, "1.2.3.4");

        cached.Should().BeTrue();
        returned.Should().NotBeNull();
        returned!.Value.Should().Be("1.2.3.4");
        returned.ConfidenceScore.Should().Be(90);
        returned.ThreatLevel.Should().Be("Critical");
    }

    [Fact]
    public async Task Cache_Key_Differs_By_Adapter_Type_And_Value()
    {
        var (cache, _) = Make();
        var hit1 = new ThreatFeedHit(IndicatorType.IpAddress, "1.1.1.1", "A", 50, "T", "L");
        var hit2 = new ThreatFeedHit(IndicatorType.IpAddress, "1.1.1.1", "B", 80, "T", "H");

        await cache.SetHitAsync("AbuseIPDB", IndicatorType.IpAddress, "1.1.1.1", hit1);
        await cache.SetHitAsync("VirusTotal", IndicatorType.IpAddress, "1.1.1.1", hit2);

        var (_, retrievedA) = await cache.TryGetAsync("AbuseIPDB", IndicatorType.IpAddress, "1.1.1.1");
        var (_, retrievedB) = await cache.TryGetAsync("VirusTotal", IndicatorType.IpAddress, "1.1.1.1");

        retrievedA!.Source.Should().Be("A");
        retrievedB!.Source.Should().Be("B");
    }

    [Fact]
    public async Task Cache_Lookup_Is_Case_Insensitive_On_Value()
    {
        var (cache, _) = Make();
        var hit = new ThreatFeedHit(IndicatorType.Domain, "evil.com", "S", 80, "T", "L");
        await cache.SetHitAsync("S", IndicatorType.Domain, "evil.com", hit);

        var (cachedUpper, hitUpper) = await cache.TryGetAsync("S", IndicatorType.Domain, "EVIL.COM");
        cachedUpper.Should().BeTrue();
        hitUpper!.Value.Should().Be("evil.com");
    }

    [Fact]
    public async Task Corrupted_Json_Treated_As_Cache_Miss()
    {
        var (cache, backing) = Make();
        var key = "ti:S:Domain:bad.com";
        await backing.SetAsync(key, Encoding.UTF8.GetBytes("not-valid-json"));

        var (cached, hit) = await cache.TryGetAsync("S", IndicatorType.Domain, "bad.com");
        cached.Should().BeFalse();
        hit.Should().BeNull();
    }
}
