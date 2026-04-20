using System.Text.Json;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.ThreatIntel;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// Handles log ingestion: normalization, queuing for background processing,
/// enrichment via threat intelligence lookup, and bulk storage.
/// </summary>
public class LogIngestionService : ILogIngestionService
{
    private readonly SOCDbContext _context;
    private readonly Channel<Log> _processingChannel;
    private readonly ThreatFeedCoordinator _threatFeedCoordinator;
    private readonly ILogger<LogIngestionService> _logger;

    public LogIngestionService(
        SOCDbContext context,
        Channel<Log> processingChannel,
        ThreatFeedCoordinator threatFeedCoordinator,
        ILogger<LogIngestionService> logger)
    {
        _context = context;
        _processingChannel = processingChannel;
        _threatFeedCoordinator = threatFeedCoordinator;
        _logger = logger;
    }

    /// <summary>
    /// Ingest a single log entry: normalize, persist, and queue for background enrichment.
    /// </summary>
    public async Task<long> IngestSingleAsync(LogIngestionDto dto)
    {
        var log = NormalizeToLog(dto);

        _context.Logs.Add(log);
        await _context.SaveChangesAsync();

        // Queue for background enrichment (non-blocking)
        await _processingChannel.Writer.WriteAsync(log);

        _logger.LogDebug("Ingested log {Id} from endpoint {EndpointId}", log.Id, log.EndpointId);
        return log.Id;
    }

    /// <summary>
    /// Ingest a batch of log entries: normalize, bulk persist, and queue for enrichment.
    /// </summary>
    public async Task<BatchIngestionResultDto> IngestBatchAsync(BatchLogIngestionDto batchDto)
    {
        var logs = new List<Log>(batchDto.Logs.Count);
        var failed = 0;

        foreach (var dto in batchDto.Logs)
        {
            try
            {
                var log = NormalizeToLog(dto);
                log.EndpointId = batchDto.EndpointId; // Override with batch-level endpoint
                logs.Add(log);
            }
            catch (Exception ex)
            {
                failed++;
                _logger.LogWarning(ex, "Failed to normalize log entry from {EndpointId}", batchDto.EndpointId);
            }
        }

        if (logs.Count > 0)
        {
            _context.Logs.AddRange(logs);
            await _context.SaveChangesAsync();

            // Queue all for background enrichment
            foreach (var log in logs)
            {
                await _processingChannel.Writer.WriteAsync(log);
            }
        }

        _logger.LogInformation("Batch ingested {Accepted}/{Total} logs from endpoint {EndpointId}",
            logs.Count, batchDto.Logs.Count, batchDto.EndpointId);

        return new BatchIngestionResultDto
        {
            Accepted = logs.Count,
            Failed = failed,
            Total = batchDto.Logs.Count,
            LogIds = logs.Select(l => l.Id).ToList()
        };
    }

    /// <summary>
    /// Enrich a log with threat intelligence data (called from background worker).
    /// Hot-path uses local-DB-only matches via ThreatFeedCoordinator (useExternal=false)
    /// — the local DB is kept current by ThreatFeedSyncJob's bulk pulls every 6h,
    /// so we never burn external API budget on per-log lookups.
    /// </summary>
    public async Task EnrichLogAsync(Log log)
    {
        var matches = await _threatFeedCoordinator.EnrichLogFieldsAsync(
            sourceIp: log.SourceIP,
            destIp: null,
            fileHash: null,
            domain: log.Hostname,
            useExternal: false);

        if (matches.Count == 0) return;

        // Pick the highest threat level across all matches to elevate log severity
        var highestLevel = matches
            .SelectMany(r => r.Matches)
            .Select(m => m.ThreatLevel)
            .OrderByDescending(SeverityRank)
            .FirstOrDefault();

        if (!string.IsNullOrEmpty(highestLevel))
            log.Severity = ElevateSeverity(log.Severity, highestLevel);

        log.NormalizedData = JsonSerializer.Serialize(new
        {
            threatIntel = new
            {
                matched = true,
                matchCount = matches.Sum(r => r.MatchCount),
                fields = matches.Select(r => new
                {
                    field = r.QueryType,
                    value = r.QueryValue,
                    sources = r.Matches.Select(m => m.Source).Distinct(),
                    highestThreat = r.Matches.OrderByDescending(m => SeverityRank(m.ThreatLevel)).FirstOrDefault()?.ThreatLevel
                })
            }
        });

        _context.Logs.Update(log);
        await _context.SaveChangesAsync();
    }

    private static int SeverityRank(string? level) => level?.ToLowerInvariant() switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
    };

    /// <summary>
    /// Normalize a DTO into a Log entity with common event schema.
    /// </summary>
    private static Log NormalizeToLog(LogIngestionDto dto)
    {
        return new Log
        {
            EndpointId = dto.EndpointId,
            Source = dto.Source.Trim(),
            EventType = dto.EventType.Trim(),
            Severity = NormalizeSeverity(dto.Severity),
            RawData = dto.RawData,
            SourceIP = dto.SourceIP?.Trim(),
            Hostname = dto.Hostname?.Trim(),
            Username = dto.Username?.Trim(),
            ProcessId = dto.ProcessId,
            ProcessName = dto.ProcessName?.Trim(),
            Timestamp = dto.Timestamp.ToUniversalTime(),
            IngestedAt = DateTime.UtcNow
        };
    }

    private static string NormalizeSeverity(string severity) =>
        severity?.Trim() switch
        {
            "Critical" or "critical" or "CRITICAL" => "Critical",
            "High" or "high" or "HIGH" => "High",
            "Medium" or "medium" or "MEDIUM" => "Medium",
            _ => "Low"
        };

    private static string ElevateSeverity(string current, string threat)
    {
        var levels = new Dictionary<string, int>
        {
            ["Low"] = 0, ["Medium"] = 1, ["High"] = 2, ["Critical"] = 3
        };

        var currentLevel = levels.GetValueOrDefault(current, 0);
        var threatLevel = levels.GetValueOrDefault(threat, 0);

        return threatLevel > currentLevel ? threat : current;
    }
}
