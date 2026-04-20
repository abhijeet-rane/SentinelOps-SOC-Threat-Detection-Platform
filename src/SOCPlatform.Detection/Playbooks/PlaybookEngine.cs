using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Detection.Playbooks;

/// <summary>
/// SOAR Playbook Engine – monitors new alerts and auto-triggers matching playbooks.
/// Handles the approval workflow and execution lifecycle:
///   Pending → Approved → Executing → Completed/Failed
/// </summary>
public class PlaybookEngine : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<PlaybookEngine> _logger;
    private readonly TimeSpan _evaluationInterval;

    public PlaybookEngine(
        IServiceProvider serviceProvider,
        ILogger<PlaybookEngine> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _evaluationInterval = TimeSpan.FromSeconds(10);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Playbook Engine started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessNewAlertsAsync(stoppingToken);
                await ProcessApprovedExecutionsAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Playbook engine cycle error");
            }

            await Task.Delay(_evaluationInterval, stoppingToken);
        }
    }

    /// <summary>
    /// Check for new alerts and create pending playbook executions for matching playbooks.
    /// </summary>
    private async Task ProcessNewAlertsAsync(CancellationToken ct)
    {
        using var scope = _serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SOCDbContext>();

        // Find alerts that are new and don't have any playbook executions yet
        var newAlerts = await context.Alerts
            .Where(a => a.Status == AlertStatus.New)
            .Where(a => !context.Set<PlaybookExecution>().Any(pe => pe.AlertId == a.Id))
            .Take(50)
            .ToListAsync(ct);

        if (newAlerts.Count == 0) return;

        // Get active playbooks
        var playbooks = await context.Set<ResponsePlaybook>()
            .Where(p => p.IsActive)
            .ToListAsync(ct);

        foreach (var alert in newAlerts)
        {
            foreach (var playbook in playbooks)
            {
                if (!ShouldTrigger(playbook, alert)) continue;

                var execution = new PlaybookExecution
                {
                    PlaybookId = playbook.Id,
                    AlertId = alert.Id,
                    Status = playbook.RequiresApproval ? "Pending" : "Approved"
                };

                // If no approval required, auto-approve
                if (!playbook.RequiresApproval)
                {
                    execution.ApprovedAt = DateTime.UtcNow;
                }

                context.Set<PlaybookExecution>().Add(execution);

                _logger.LogInformation(
                    "Playbook '{PlaybookName}' triggered for alert '{AlertTitle}' (Status: {Status})",
                    playbook.Name, alert.Title, execution.Status);
            }
        }

        await context.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Execute approved playbook actions.
    /// </summary>
    private async Task ProcessApprovedExecutionsAsync(CancellationToken ct)
    {
        using var scope = _serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SOCDbContext>();

        // Resolve actions per-scope so DbContext / adapter dependencies are scoped correctly.
        var actions = scope.ServiceProvider.GetServices<IPlaybookAction>().ToList();

        var pendingExecutions = await context.Set<PlaybookExecution>()
            .Include(pe => pe.Playbook)
            .Include(pe => pe.Alert)
            .Where(pe => pe.Status == "Approved")
            .Take(20)
            .ToListAsync(ct);

        foreach (var execution in pendingExecutions)
        {
            var handler = actions.FirstOrDefault(a => a.ActionType == execution.Playbook.ActionType);
            if (handler == null)
            {
                execution.Status = "Failed";
                execution.ErrorMessage = $"No handler registered for action type: {execution.Playbook.ActionType}";
                execution.CompletedAt = DateTime.UtcNow;
                continue;
            }

            execution.Status = "Executing";
            execution.ExecutedAt = DateTime.UtcNow;
            await context.SaveChangesAsync(ct);

            try
            {
                var result = await handler.ExecuteAsync(execution.Alert, execution.Playbook.ActionConfig, ct);
                execution.Status = "Completed";
                execution.Result = result;
                execution.CompletedAt = DateTime.UtcNow;

                _logger.LogInformation(
                    "Playbook '{PlaybookName}' completed for alert '{AlertTitle}': {Result}",
                    execution.Playbook.Name, execution.Alert.Title, result);
            }
            catch (Exception ex)
            {
                execution.Status = "Failed";
                execution.ErrorMessage = ex.Message;
                execution.CompletedAt = DateTime.UtcNow;

                _logger.LogError(ex, "Playbook '{PlaybookName}' failed for alert '{AlertTitle}'",
                    execution.Playbook.Name, execution.Alert.Title);
            }
        }

        await context.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Determine whether a playbook should trigger for a given alert based on trigger conditions.
    /// </summary>
    private static bool ShouldTrigger(ResponsePlaybook playbook, Alert alert)
    {
        if (string.IsNullOrEmpty(playbook.TriggerCondition)) return false;

        // Simple trigger condition matching (format: "field:value")
        // Examples: "severity:Critical", "rule:Brute Force Detection", "action:BlockIp"
        var parts = playbook.TriggerCondition.Split(':', 2);
        if (parts.Length != 2) return false;

        return parts[0].Trim().ToLower() switch
        {
            "severity" => alert.Severity.ToString().Equals(parts[1].Trim(), StringComparison.OrdinalIgnoreCase),
            "rule" => alert.DetectionRuleName?.Contains(parts[1].Trim(), StringComparison.OrdinalIgnoreCase) == true,
            "mitre" => alert.MitreTechnique?.Equals(parts[1].Trim(), StringComparison.OrdinalIgnoreCase) == true,
            "any" => true,
            _ => false
        };
    }
}
