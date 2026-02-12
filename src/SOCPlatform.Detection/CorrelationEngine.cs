using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Detection;

/// <summary>
/// Correlation engine that groups related alerts into incidents.
/// Uses time-window + entity-based correlation:
/// - Alerts sharing the same affected user/device/IP within a time window → single incident.
/// </summary>
public class CorrelationEngine : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<CorrelationEngine> _logger;
    private readonly TimeSpan _correlationWindow;
    private readonly TimeSpan _evaluationInterval;

    public CorrelationEngine(
        IServiceProvider serviceProvider,
        ILogger<CorrelationEngine> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _correlationWindow = TimeSpan.FromMinutes(30);
        _evaluationInterval = TimeSpan.FromSeconds(30);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Correlation Engine started (window: {Window}min)",
            _correlationWindow.TotalMinutes);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CorrelateAlertsAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Correlation cycle error");
            }

            await Task.Delay(_evaluationInterval, stoppingToken);
        }
    }

    private async Task CorrelateAlertsAsync(CancellationToken ct)
    {
        using var scope = _serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SOCDbContext>();

        // Fetch uncorrelated alerts (no incident assigned)
        var unlinkedAlerts = await context.Alerts
            .Where(a => a.IncidentId == null && a.Status == AlertStatus.New)
            .OrderBy(a => a.CreatedAt)
            .Take(200)
            .ToListAsync(ct);

        if (unlinkedAlerts.Count < 2) return;

        var processed = new HashSet<Guid>();

        foreach (var alert in unlinkedAlerts)
        {
            if (processed.Contains(alert.Id)) continue;

            // Find related alerts: same entity within time window
            var related = unlinkedAlerts
                .Where(a => a.Id != alert.Id
                    && !processed.Contains(a.Id)
                    && Math.Abs((a.CreatedAt - alert.CreatedAt).TotalMinutes) <= _correlationWindow.TotalMinutes
                    && HasEntityOverlap(alert, a))
                .ToList();

            if (related.Count == 0) continue;

            // Create incident from correlated alerts
            var allCorrelated = new List<Alert> { alert };
            allCorrelated.AddRange(related);

            var maxSeverity = allCorrelated.Max(a => a.Severity);

            var incident = new Incident
            {
                Title = $"Correlated Incident – {alert.AffectedUser ?? alert.SourceIP ?? alert.AffectedDevice}",
                Description = $"Auto-correlated {allCorrelated.Count} related alerts within {_correlationWindow.TotalMinutes} minutes. " +
                              $"Rules triggered: {string.Join(", ", allCorrelated.Select(a => a.DetectionRuleName).Distinct())}.",
                Severity = maxSeverity,
                Status = IncidentStatus.Open
            };

            context.Incidents.Add(incident);
            await context.SaveChangesAsync(ct); // Get the incident ID

            foreach (var a in allCorrelated)
            {
                a.IncidentId = incident.Id;
                processed.Add(a.Id);
            }

            await context.SaveChangesAsync(ct);

            _logger.LogInformation(
                "Created incident '{Title}' (Severity: {Severity}) from {AlertCount} correlated alerts",
                incident.Title, incident.Severity, allCorrelated.Count);
        }
    }

    /// <summary>
    /// Check if two alerts share common entities (user, device, or source IP).
    /// </summary>
    private static bool HasEntityOverlap(Alert a, Alert b)
    {
        if (!string.IsNullOrEmpty(a.AffectedUser) && a.AffectedUser == b.AffectedUser) return true;
        if (!string.IsNullOrEmpty(a.AffectedDevice) && a.AffectedDevice == b.AffectedDevice) return true;
        if (!string.IsNullOrEmpty(a.SourceIP) && a.SourceIP == b.SourceIP) return true;
        return false;
    }
}
