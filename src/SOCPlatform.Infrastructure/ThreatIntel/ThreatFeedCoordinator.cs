using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Services;
using SOCPlatform.Infrastructure.ThreatIntel.Cache;

namespace SOCPlatform.Infrastructure.ThreatIntel;

/// <summary>
/// Orchestrates real-time threat-intel enrichment across all registered adapters.
///
/// Lookup pipeline (per indicator):
///   1. Local DB exact match (fastest, free) — existing IOC table
///   2. Cache check per adapter (Redis, default 1h TTL)
///   3. Live adapter calls in parallel for cache misses
///   4. Persist new hits to ThreatIntelIndicator (UPSERT via existing service)
///   5. Return aggregated EnrichmentResultDto
///
/// Bulk sync pipeline (called by ThreatFeedSyncJob, every 6h):
///   1. Stream each adapter's bulk feed (URLhaus, ThreatFox, …)
///   2. UPSERT every hit through ThreatIntelService.CreateAsync (handles merge)
///   3. Return SyncReport with counts per source
/// </summary>
public sealed class ThreatFeedCoordinator
{
    private readonly SOCDbContext _db;
    private readonly IEnumerable<IThreatFeedAdapter> _adapters;
    private readonly IThreatIntelCache _cache;
    private readonly ThreatIntelService _legacyService;
    private readonly ILogger<ThreatFeedCoordinator> _logger;

    public ThreatFeedCoordinator(
        SOCDbContext db,
        IEnumerable<IThreatFeedAdapter> adapters,
        IThreatIntelCache cache,
        ThreatIntelService legacyService,
        ILogger<ThreatFeedCoordinator> logger)
    {
        _db = db;
        _adapters = adapters;
        _cache = cache;
        _legacyService = legacyService;
        _logger = logger;
    }

    public IReadOnlyList<string> AdapterNames => _adapters.Select(a => a.Name).ToList();

    /// <summary>
    /// Enrich a single value against local DB and (optionally) live adapters.
    /// Cache-first per adapter to avoid burning rate-limited API budgets.
    /// </summary>
    public async Task<EnrichmentResultDto> EnrichAsync(
        string value, IndicatorType? type, bool useExternal = true, CancellationToken ct = default)
    {
        var normalized = value.Trim().ToLowerInvariant();
        var localResult = await _legacyService.EnrichAsync(value, type?.ToString());

        if (!useExternal) return localResult;

        // Run live lookups in parallel against every adapter that supports the type.
        // If type is null we cannot dispatch — caller should narrow, otherwise skip externals.
        if (type is null) return localResult;

        var lookupTasks = _adapters
            .Where(a => a.SupportsType(type.Value))
            .Select(a => LookupOneAsync(a, type.Value, normalized, ct))
            .ToList();

        var hits = (await Task.WhenAll(lookupTasks))
            .Where(h => h is not null)
            .Cast<ThreatFeedHit>()
            .ToList();

        if (hits.Count == 0) return localResult;

        // Persist (UPSERT via existing CreateAsync — does merge-on-conflict by (type, value))
        foreach (var hit in hits)
        {
            try
            {
                await _legacyService.CreateAsync(ToCreateDto(hit));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to upsert hit from {Source} for {Value}", hit.Source, hit.Value);
            }
        }

        // Re-query so caller gets the freshly-persisted matches in the result
        return await _legacyService.EnrichAsync(value, type.Value.ToString());
    }

    /// <summary>
    /// Enrich every relevant field of a Log/SecurityEvent in parallel.
    /// Returns only the matches (non-empty results).
    /// </summary>
    public async Task<IReadOnlyList<EnrichmentResultDto>> EnrichLogFieldsAsync(
        string? sourceIp, string? destIp, string? fileHash, string? domain,
        bool useExternal = true, CancellationToken ct = default)
    {
        var tasks = new List<Task<EnrichmentResultDto>>();
        if (!string.IsNullOrWhiteSpace(sourceIp)) tasks.Add(EnrichAsync(sourceIp!, IndicatorType.IpAddress, useExternal, ct));
        if (!string.IsNullOrWhiteSpace(destIp))   tasks.Add(EnrichAsync(destIp!,   IndicatorType.IpAddress, useExternal, ct));
        if (!string.IsNullOrWhiteSpace(fileHash)) tasks.Add(EnrichAsync(fileHash!, IndicatorType.FileHash,  useExternal, ct));
        if (!string.IsNullOrWhiteSpace(domain))   tasks.Add(EnrichAsync(domain!,   IndicatorType.Domain,    useExternal, ct));

        var results = await Task.WhenAll(tasks);
        return results.Where(r => r.MatchCount > 0).ToList();
    }

    /// <summary>
    /// Pull the full bulk feed from every adapter that exposes one and UPSERT
    /// every indicator. Called by ThreatFeedSyncJob on a 6-hour cadence.
    /// </summary>
    public async Task<SyncReport> SyncAllAsync(CancellationToken ct = default)
    {
        var report = new SyncReport();
        var startedAt = DateTime.UtcNow;

        foreach (var adapter in _adapters)
        {
            var perSource = new SyncReport.SourceStats(adapter.Name);
            try
            {
                await foreach (var hit in adapter.StreamBulkAsync(ct))
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        await _legacyService.CreateAsync(ToCreateDto(hit));
                        perSource.Imported++;
                    }
                    catch (Exception ex)
                    {
                        perSource.Failed++;
                        _logger.LogDebug(ex, "Skip indicator from {Source}: {Value}", adapter.Name, hit.Value);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Bulk sync failed for {Source}", adapter.Name);
                perSource.Errored = true;
            }
            report.Sources.Add(perSource);
        }

        report.DurationSeconds = (DateTime.UtcNow - startedAt).TotalSeconds;
        _logger.LogInformation(
            "Threat-feed sync complete: {Total} indicators across {Sources} sources in {Sec:F1}s",
            report.Sources.Sum(s => s.Imported), report.Sources.Count, report.DurationSeconds);
        return report;
    }

    // ───────────────────────────────────────────────────────────────────────

    private async Task<ThreatFeedHit?> LookupOneAsync(
        IThreatFeedAdapter adapter, IndicatorType type, string value, CancellationToken ct)
    {
        var (cached, cachedHit) = await _cache.TryGetAsync(adapter.Name, type, value, ct);
        if (cached) return cachedHit; // Either a cached hit OR a cached miss (null)

        var hit = await adapter.LookupAsync(type, value, ct);
        if (hit is null)
            await _cache.SetMissAsync(adapter.Name, type, value, ct);
        else
            await _cache.SetHitAsync(adapter.Name, type, value, hit, ct);

        return hit;
    }

    private static CreateThreatIntelDto ToCreateDto(ThreatFeedHit hit) => new()
    {
        IndicatorType = hit.IndicatorType.ToString(),
        Value = hit.Value,
        Source = hit.Source,
        ConfidenceScore = hit.ConfidenceScore,
        ThreatType = hit.ThreatType,
        ThreatLevel = hit.ThreatLevel,
        Description = hit.Description,
        Tags = hit.Tags,
        GeoCountry = hit.GeoCountry,
        ASN = hit.Asn,
        MitreTechniques = hit.MitreTechniques,
        ExpiresAt = hit.ExpiresAt
    };
}

public sealed class SyncReport
{
    public List<SourceStats> Sources { get; } = new();
    public double DurationSeconds { get; set; }
    public int TotalImported => Sources.Sum(s => s.Imported);
    public int TotalFailed => Sources.Sum(s => s.Failed);
    public int ErroredSourceCount => Sources.Count(s => s.Errored);

    public sealed class SourceStats
    {
        public SourceStats(string source) => Source = source;
        public string Source { get; }
        public int Imported { get; set; }
        public int Failed { get; set; }
        public bool Errored { get; set; }
    }
}
