using System.Text.Json;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// Handles log ingestion: normalization, queuing for background processing,
/// enrichment via threat intelligence lookup, and bulk storage.
/// </summary>
public class LogIngestionService : ILogIngestionService
{
    private readonly SOCDbContext _context;
    private readonly Channel<Log> _processingChannel;
    private readonly ILogger<LogIngestionService> _logger;

    public LogIngestionService(
        SOCDbContext context,
        Channel<Log> processingChannel,
        ILogger<LogIngestionService> logger)
    {
        _context = context;
        _processingChannel = processingChannel;
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
    /// </summary>
    public async Task EnrichLogAsync(Log log)
    {
        var enrichments = new Dictionary<string, object>();

        // Check source IP against threat intel indicators
        if (!string.IsNullOrEmpty(log.SourceIP))
        {
            var ipThreat = await _context.ThreatIntelIndicators
                .Where(t => t.IsActive &&
                            t.IndicatorType == Core.Enums.IndicatorType.IpAddress &&
                            t.Value == log.SourceIP)
                .Select(t => new { t.ThreatLevel, t.Description, t.Source })
                .FirstOrDefaultAsync();

            if (ipThreat != null)
            {
                enrichments["threatIntel"] = new
                {
                    matched = true,
                    indicator = "IpAddress",
                    ipThreat.ThreatLevel,
                    ipThreat.Description,
                    ipThreat.Source
                };
                log.Severity = ElevateSeverity(log.Severity, ipThreat.ThreatLevel);
            }
        }

        // Check hostname against domain indicators
        if (!string.IsNullOrEmpty(log.Hostname))
        {
            var domainThreat = await _context.ThreatIntelIndicators
                .Where(t => t.IsActive &&
                            t.IndicatorType == Core.Enums.IndicatorType.Domain &&
                            t.Value == log.Hostname)
                .Select(t => new { t.ThreatLevel, t.Description, t.Source })
                .FirstOrDefaultAsync();

            if (domainThreat != null)
            {
                enrichments["domainThreat"] = new
                {
                    matched = true,
                    indicator = "Domain",
                    domainThreat.ThreatLevel,
                    domainThreat.Description,
                    domainThreat.Source
                };
                log.Severity = ElevateSeverity(log.Severity, domainThreat.ThreatLevel);
            }
        }

        if (enrichments.Count > 0)
        {
            log.NormalizedData = JsonSerializer.Serialize(enrichments);
            _context.Logs.Update(log);
            await _context.SaveChangesAsync();
        }
    }

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
