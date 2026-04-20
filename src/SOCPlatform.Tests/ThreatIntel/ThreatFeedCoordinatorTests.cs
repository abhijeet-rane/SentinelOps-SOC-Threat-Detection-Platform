using System.Runtime.CompilerServices;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Services;
using SOCPlatform.Infrastructure.ThreatIntel;
using SOCPlatform.Infrastructure.ThreatIntel.Cache;

namespace SOCPlatform.Tests.ThreatIntel;

public class ThreatFeedCoordinatorTests
{
    private static SOCDbContext NewDb()
    {
        var opts = new DbContextOptionsBuilder<SOCDbContext>()
            .UseInMemoryDatabase($"tic-{Guid.NewGuid()}").Options;
        return new SOCDbContext(opts);
    }

    private static ThreatIntelService NewLegacyService(SOCDbContext db) =>
        new(db, NullLogger<ThreatIntelService>.Instance);

    [Fact]
    public async Task EnrichAsync_With_UseExternal_False_Returns_Local_Only_And_Skips_Adapters()
    {
        using var db = NewDb();
        var calledAdapter = false;
        var adapter = new FakeAdapter(IndicatorType.IpAddress, hit: null, onLookup: () => calledAdapter = true);
        var cache = new Mock<IThreatIntelCache>(MockBehavior.Strict).Object; // would throw if any method called

        var coord = new ThreatFeedCoordinator(
            db, [adapter], cache, NewLegacyService(db), NullLogger<ThreatFeedCoordinator>.Instance);

        var result = await coord.EnrichAsync("1.1.1.1", IndicatorType.IpAddress, useExternal: false);

        result.IsMalicious.Should().BeFalse();
        calledAdapter.Should().BeFalse();
    }

    [Fact]
    public async Task EnrichAsync_External_Cache_Hit_Skips_Adapter_LookupAsync()
    {
        using var db = NewDb();
        var adapter = new FakeAdapter(IndicatorType.IpAddress,
            hit: new ThreatFeedHit(IndicatorType.IpAddress, "1.1.1.1", "AbuseIPDB", 99, "C2", "Critical"));
        var cache = new InMemoryFakeCache();

        // Pre-seed cache as a hit
        await cache.SetHitAsync("AbuseIPDB", IndicatorType.IpAddress, "1.1.1.1",
            new ThreatFeedHit(IndicatorType.IpAddress, "1.1.1.1", "AbuseIPDB", 99, "C2", "Critical"));

        var coord = new ThreatFeedCoordinator(
            db, [adapter], cache, NewLegacyService(db), NullLogger<ThreatFeedCoordinator>.Instance);

        await coord.EnrichAsync("1.1.1.1", IndicatorType.IpAddress, useExternal: true);

        adapter.LookupCalls.Should().Be(0, "cache hit must short-circuit");
    }

    [Fact]
    public async Task EnrichAsync_External_Persists_New_Hit_Into_DB_So_Local_Match_Surfaces()
    {
        using var db = NewDb();
        var hit = new ThreatFeedHit(IndicatorType.IpAddress, "9.9.9.9", "AbuseIPDB", 95, "Botnet", "Critical");
        var adapter = new FakeAdapter(IndicatorType.IpAddress, hit: hit);
        var cache = new InMemoryFakeCache();

        var coord = new ThreatFeedCoordinator(
            db, [adapter], cache, NewLegacyService(db), NullLogger<ThreatFeedCoordinator>.Instance);

        var result = await coord.EnrichAsync("9.9.9.9", IndicatorType.IpAddress, useExternal: true);

        result.IsMalicious.Should().BeTrue();
        result.MatchCount.Should().BeGreaterThan(0);
        (await db.ThreatIntelIndicators.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task EnrichAsync_External_Caches_Miss_So_Repeat_Skips_Adapter()
    {
        using var db = NewDb();
        var adapter = new FakeAdapter(IndicatorType.IpAddress, hit: null);
        var cache = new InMemoryFakeCache();

        var coord = new ThreatFeedCoordinator(
            db, [adapter], cache, NewLegacyService(db), NullLogger<ThreatFeedCoordinator>.Instance);

        await coord.EnrichAsync("1.1.1.1", IndicatorType.IpAddress, useExternal: true); // first call: hits adapter
        await coord.EnrichAsync("1.1.1.1", IndicatorType.IpAddress, useExternal: true); // second call: cache miss is cached

        adapter.LookupCalls.Should().Be(1);
    }

    [Fact]
    public async Task EnrichAsync_Skips_Adapter_That_Doesnt_Support_Type()
    {
        using var db = NewDb();
        var adapter = new FakeAdapter(IndicatorType.IpAddress, hit: null);
        var cache = new InMemoryFakeCache();

        var coord = new ThreatFeedCoordinator(
            db, [adapter], cache, NewLegacyService(db), NullLogger<ThreatFeedCoordinator>.Instance);

        await coord.EnrichAsync("evil.com", IndicatorType.Domain, useExternal: true);

        adapter.LookupCalls.Should().Be(0);
    }

    [Fact]
    public async Task SyncAllAsync_Imports_All_Hits_From_Each_Adapter()
    {
        using var db = NewDb();
        var ipAdapter = new FakeAdapter(IndicatorType.IpAddress,
            bulk:
            [
                new ThreatFeedHit(IndicatorType.IpAddress, "1.1.1.1", "FakeIPDB", 90, "Botnet", "Critical"),
                new ThreatFeedHit(IndicatorType.IpAddress, "2.2.2.2", "FakeIPDB", 75, "Scanner", "High"),
            ]);
        var domainAdapter = new FakeAdapter(IndicatorType.Domain,
            bulk:
            [
                new ThreatFeedHit(IndicatorType.Domain, "evil.com", "FakeFeed", 99, "C2", "Critical"),
            ]);
        var cache = new InMemoryFakeCache();

        var coord = new ThreatFeedCoordinator(
            db, [ipAdapter, domainAdapter], cache, NewLegacyService(db), NullLogger<ThreatFeedCoordinator>.Instance);

        var report = await coord.SyncAllAsync();

        report.TotalImported.Should().Be(3);
        report.TotalFailed.Should().Be(0);
        report.Sources.Should().HaveCount(2);
        (await db.ThreatIntelIndicators.CountAsync()).Should().Be(3);
    }

    [Fact]
    public async Task EnrichLogFieldsAsync_Returns_Only_Matched_Fields()
    {
        using var db = NewDb();
        var adapter = new FakeAdapter(IndicatorType.IpAddress,
            hit: new ThreatFeedHit(IndicatorType.IpAddress, "1.1.1.1", "F", 90, "T", "Critical"));
        var cache = new InMemoryFakeCache();

        var coord = new ThreatFeedCoordinator(
            db, [adapter], cache, NewLegacyService(db), NullLogger<ThreatFeedCoordinator>.Instance);

        var matches = await coord.EnrichLogFieldsAsync(
            sourceIp: "1.1.1.1", destIp: "8.8.8.8", fileHash: null, domain: null, useExternal: true);

        // 1.1.1.1 hits, 8.8.8.8 doesn't (adapter only returns hit for the value it was constructed with)
        matches.Should().HaveCount(1);
        matches[0].QueryValue.Should().Be("1.1.1.1");
    }

    // ───────────────────────────────────────────────────────────────────────
    //  Test doubles
    // ───────────────────────────────────────────────────────────────────────

    private sealed class FakeAdapter : IThreatFeedAdapter
    {
        private readonly IndicatorType _supports;
        private readonly ThreatFeedHit? _lookupHit;
        private readonly IReadOnlyList<ThreatFeedHit> _bulk;
        private readonly Action? _onLookup;
        public int LookupCalls { get; private set; }

        public FakeAdapter(
            IndicatorType supports,
            ThreatFeedHit? hit = null,
            IReadOnlyList<ThreatFeedHit>? bulk = null,
            Action? onLookup = null)
        {
            _supports = supports;
            _lookupHit = hit;
            _bulk = bulk ?? Array.Empty<ThreatFeedHit>();
            _onLookup = onLookup;
        }

        public string Name => _lookupHit?.Source ?? _bulk.FirstOrDefault()?.Source ?? "FakeAdapter";

        public bool SupportsType(IndicatorType type) => type == _supports;

        public Task<ThreatFeedHit?> LookupAsync(IndicatorType type, string value, CancellationToken ct = default)
        {
            LookupCalls++;
            _onLookup?.Invoke();

            // Only return the hit if the value matches the seeded one
            if (_lookupHit is not null && string.Equals(_lookupHit.Value, value, StringComparison.OrdinalIgnoreCase))
                return Task.FromResult<ThreatFeedHit?>(_lookupHit);

            return Task.FromResult<ThreatFeedHit?>(null);
        }

        public async IAsyncEnumerable<ThreatFeedHit> StreamBulkAsync([EnumeratorCancellation] CancellationToken ct = default)
        {
            foreach (var hit in _bulk) { yield return hit; await Task.Yield(); }
        }
    }

    private sealed class InMemoryFakeCache : IThreatIntelCache
    {
        private readonly Dictionary<string, ThreatFeedHit?> _store = new();
        private readonly HashSet<string> _missKeys = new();

        public Task<(bool Cached, ThreatFeedHit? Hit)> TryGetAsync(string adapter, IndicatorType type, string value, CancellationToken ct = default)
        {
            var key = $"{adapter}:{type}:{value.ToLowerInvariant()}";
            if (_missKeys.Contains(key)) return Task.FromResult((true, (ThreatFeedHit?)null));
            return _store.TryGetValue(key, out var hit) ? Task.FromResult((true, hit)) : Task.FromResult((false, (ThreatFeedHit?)null));
        }

        public Task SetHitAsync(string adapter, IndicatorType type, string value, ThreatFeedHit hit, CancellationToken ct = default)
        {
            _store[$"{adapter}:{type}:{value.ToLowerInvariant()}"] = hit;
            return Task.CompletedTask;
        }

        public Task SetMissAsync(string adapter, IndicatorType type, string value, CancellationToken ct = default)
        {
            _missKeys.Add($"{adapter}:{type}:{value.ToLowerInvariant()}");
            return Task.CompletedTask;
        }
    }
}
