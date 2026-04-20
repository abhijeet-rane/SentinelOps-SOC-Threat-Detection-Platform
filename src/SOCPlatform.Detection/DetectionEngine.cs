using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Detection.Rules;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Observability;

namespace SOCPlatform.Detection;

/// <summary>
/// Core detection engine that periodically evaluates security events against all active detection rules.
/// Runs as a BackgroundService, querying recent events and generating alerts.
/// </summary>
public class DetectionEngine : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<DetectionEngine> _logger;
    private readonly List<IDetectionRule> _rules;
    private readonly TimeSpan _evaluationInterval;

    private DateTime _lastEvaluationTime = DateTime.UtcNow;

    public DetectionEngine(
        IServiceProvider serviceProvider,
        ILogger<DetectionEngine> logger,
        IEnumerable<IDetectionRule> rules,
        TimeSpan? evaluationInterval = null)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _rules = rules.ToList();
        _evaluationInterval = evaluationInterval ?? TimeSpan.FromSeconds(15);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Detection Engine started with {RuleCount} rules", _rules.Count);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunDetectionCycleAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Detection cycle error");
            }

            await Task.Delay(_evaluationInterval, stoppingToken);
        }
    }

    private async Task RunDetectionCycleAsync(CancellationToken ct)
    {
        using var scope = _serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
        var metrics = scope.ServiceProvider.GetService<SocMetrics>();

        // Trace span for the full cycle (visible in Jaeger when OTLP exporter is enabled)
        using var activity = SocActivitySource.Instance.StartActivity("detection.cycle", ActivityKind.Internal);

        var since = _lastEvaluationTime;
        _lastEvaluationTime = DateTime.UtcNow;

        // Fetch recent security events
        var recentEvents = await context.SecurityEvents
            .Where(e => e.Timestamp >= since)
            .Include(e => e.Log)
            .OrderBy(e => e.Timestamp)
            .Take(1000)
            .ToListAsync(ct);

        if (recentEvents.Count == 0) return;

        _logger.LogDebug("Evaluating {EventCount} events against {RuleCount} rules",
            recentEvents.Count, _rules.Count(r => r.IsEnabled));

        var allAlerts = new List<Alert>();

        foreach (var rule in _rules.Where(r => r.IsEnabled))
        {
            var ruleTag = new KeyValuePair<string, object?>("rule", rule.Name);
            var sw = Stopwatch.StartNew();
            try
            {
                var alerts = await rule.EvaluateAsync(recentEvents, ct);
                sw.Stop();
                metrics?.DetectionDurationMs.Record(sw.Elapsed.TotalMilliseconds, ruleTag);

                if (alerts.Count > 0)
                {
                    _logger.LogInformation("Rule '{RuleName}' generated {AlertCount} alert(s)",
                        rule.Name, alerts.Count);

                    // Set detection rule IDs from DB if available
                    var dbRule = await context.DetectionRules
                        .FirstOrDefaultAsync(r => r.Name == rule.Name, ct);

                    foreach (var alert in alerts)
                    {
                        alert.DetectionRuleId = dbRule?.Id;
                        alert.SlaDeadline = CalculateSlaDeadline(alert.Severity);

                        // Counter: one hit per alert, tagged by severity + rule
                        metrics?.AlertsTotal.Add(1,
                            new KeyValuePair<string, object?>("severity", alert.Severity.ToString()),
                            ruleTag);
                    }

                    allAlerts.AddRange(alerts);
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Error evaluating rule '{RuleName}'", rule.Name);
                activity?.AddEvent(new ActivityEvent("rule.error",
                    tags: new ActivityTagsCollection { { "rule", rule.Name }, { "error", ex.Message } }));
            }
        }

        activity?.SetTag("alerts.generated", allAlerts.Count);
        activity?.SetTag("events.processed", recentEvents.Count);

        if (allAlerts.Count > 0)
        {
            context.Alerts.AddRange(allAlerts);
            await context.SaveChangesAsync(ct);
            _logger.LogInformation("Persisted {AlertCount} alerts to database", allAlerts.Count);

            // Fire-and-forget push to connected dashboard clients. Notifier
            // swallows its own errors so a SignalR hiccup can't fail the cycle.
            var notifier = scope.ServiceProvider.GetService<IAlertNotifier>();
            if (notifier is not null)
                await notifier.BroadcastAlertsAsync(allAlerts, ct);
        }
    }

    /// <summary>
    /// Calculate SLA deadline based on alert severity.
    /// Critical: 1h, High: 4h, Medium: 8h, Low: 24h
    /// </summary>
    private static DateTime CalculateSlaDeadline(Core.Enums.Severity severity) => severity switch
    {
        Core.Enums.Severity.Critical => DateTime.UtcNow.AddHours(1),
        Core.Enums.Severity.High => DateTime.UtcNow.AddHours(4),
        Core.Enums.Severity.Medium => DateTime.UtcNow.AddHours(8),
        Core.Enums.Severity.Low => DateTime.UtcNow.AddHours(24),
        _ => DateTime.UtcNow.AddHours(24)
    };
}
