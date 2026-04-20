using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Observability;

namespace SOCPlatform.Infrastructure.Jobs;

/// <summary>
/// Hangfire-recurring every minute. Counts alerts whose <c>SlaDeadline</c> has
/// just passed without resolution and records one metric hit per alert into
/// <c>socp_sla_breaches_total</c>. Idempotent via a simple watermark
/// (<see cref="_lastSweep"/>) — re-runs don't double-count.
///
/// The counter is used by the Grafana dashboard to show SLA-breach rate per
/// severity and by alerting rules (e.g. page on-call when Critical breaches &gt; 0).
/// </summary>
public sealed class SlaBreachTrackerJob
{
    public const string RecurringJobId = "sla-breach-tracker";

    private static DateTime _lastSweep = DateTime.UtcNow.AddMinutes(-1);

    private readonly SOCDbContext _db;
    private readonly SocMetrics _metrics;
    private readonly ILogger<SlaBreachTrackerJob> _logger;

    public SlaBreachTrackerJob(SOCDbContext db, SocMetrics metrics, ILogger<SlaBreachTrackerJob> logger)
    {
        _db = db;
        _metrics = metrics;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;

        var breached = await _db.Alerts
            .Where(a => a.SlaDeadline != null
                     && a.SlaDeadline <= now
                     && a.SlaDeadline > _lastSweep
                     && a.Status != AlertStatus.Resolved
                     && a.Status != AlertStatus.Closed)
            .Select(a => new { a.Severity })
            .ToListAsync(ct);

        foreach (var b in breached)
        {
            _metrics.SlaBreachesTotal.Add(1, new KeyValuePair<string, object?>("severity", b.Severity.ToString()));
        }

        if (breached.Count > 0)
            _logger.LogWarning("[SLA] {Count} alert(s) breached SLA in the last minute", breached.Count);

        _lastSweep = now;
    }
}
