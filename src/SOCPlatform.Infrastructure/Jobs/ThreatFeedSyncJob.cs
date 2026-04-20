using Microsoft.Extensions.Logging;
using SOCPlatform.Infrastructure.ThreatIntel;

namespace SOCPlatform.Infrastructure.Jobs;

/// <summary>
/// Hangfire-recurring job: pulls every adapter's bulk feed and UPSERTs IOCs.
/// Registered with cron "0 */6 * * *" (every 6 hours) at startup, plus
/// available on-demand via /api/v1/threatintel/sync.
/// </summary>
public sealed class ThreatFeedSyncJob
{
    public const string RecurringJobId = "threat-feed-sync";

    private readonly ThreatFeedCoordinator _coordinator;
    private readonly ILogger<ThreatFeedSyncJob> _logger;

    public ThreatFeedSyncJob(ThreatFeedCoordinator coordinator, ILogger<ThreatFeedSyncJob> logger)
    {
        _coordinator = coordinator;
        _logger = logger;
    }

    /// <summary>Entry point invoked by Hangfire (and the manual /sync endpoint).</summary>
    public async Task RunAsync(CancellationToken ct = default)
    {
        _logger.LogInformation("Threat-feed sync starting…");
        var report = await _coordinator.SyncAllAsync(ct);
        _logger.LogInformation(
            "Threat-feed sync done: imported={Imported} failed={Failed} errored_sources={Err} dur={Sec:F1}s",
            report.TotalImported, report.TotalFailed, report.ErroredSourceCount, report.DurationSeconds);
    }
}
