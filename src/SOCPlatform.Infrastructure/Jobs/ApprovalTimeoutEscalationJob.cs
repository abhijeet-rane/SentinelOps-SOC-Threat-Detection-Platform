using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Soar;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Jobs;

/// <summary>
/// Hangfire-recurring (every 5 min): finds PlaybookExecutions still in
/// "Pending" state past <see cref="SoarOptions.ApprovalTimeoutMinutes"/> and
/// notifies the SOC Manager via the configured INotificationAdapter so they
/// can act. Optionally auto-rejects after a hard timeout.
/// Idempotent — flags rows it has already escalated via PlaybookExecution.Result.
/// </summary>
public sealed class ApprovalTimeoutEscalationJob
{
    public const string RecurringJobId = "soar-approval-timeout-escalation";
    private const string EscalationMarker = "[ESCALATED-PENDING-APPROVAL]";

    private readonly SOCDbContext _db;
    private readonly INotificationAdapter _notify;
    private readonly SoarOptions _options;
    private readonly ILogger<ApprovalTimeoutEscalationJob> _logger;

    public ApprovalTimeoutEscalationJob(
        SOCDbContext db,
        INotificationAdapter notify,
        IOptions<SoarOptions> options,
        ILogger<ApprovalTimeoutEscalationJob> logger)
    {
        _db = db;
        _notify = notify;
        _options = options.Value;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var escalateThreshold = now.AddMinutes(-_options.ApprovalTimeoutMinutes);
        var rejectThreshold   = _options.AutoRejectAfterMinutes > 0
            ? now.AddMinutes(-_options.AutoRejectAfterMinutes)
            : (DateTime?)null;

        var staleApprovals = await _db.PlaybookExecutions
            .Include(e => e.Playbook)
            .Include(e => e.Alert)
            .Where(e => e.Status == "Pending" && e.CreatedAt <= escalateThreshold)
            .Take(50)
            .ToListAsync(ct);

        if (staleApprovals.Count == 0)
        {
            _logger.LogDebug("[SOAR] No stale pending approvals");
            return;
        }

        int notified = 0, autoRejected = 0;

        foreach (var execution in staleApprovals)
        {
            var ageMinutes = (now - execution.CreatedAt).TotalMinutes;

            // 1. Auto-reject hard-timeout violations first
            if (rejectThreshold.HasValue && execution.CreatedAt <= rejectThreshold.Value)
            {
                execution.Status = "Rejected";
                execution.CompletedAt = now;
                execution.ErrorMessage = $"Auto-rejected: pending approval > {_options.AutoRejectAfterMinutes}min";
                autoRejected++;
                _logger.LogWarning("[SOAR] Auto-rejected execution {Id} after {Age:F0}min", execution.Id, ageMinutes);
                continue;
            }

            // 2. Skip rows we've already notified about
            if (execution.Result?.Contains(EscalationMarker) == true) continue;

            // 3. Notify SOC Manager — once per stale execution
            var req = new NotificationRequest(
                Subject: $"Pending playbook approval has been waiting {ageMinutes:F0}min",
                HtmlBody: BuildEscalationHtml(execution.Playbook.Name, execution.Alert.Title, execution.Alert.Severity.ToString(), ageMinutes),
                PlainTextBody: $"Playbook '{execution.Playbook.Name}' has been awaiting approval for {ageMinutes:F0} minutes (alert: {execution.Alert.Title}).",
                Severity: execution.Alert.Severity.ToString(),
                AlertId: execution.Alert.Id);

            var result = await _notify.NotifyAsync(req, ct);
            execution.Result = $"{EscalationMarker} notified={result.Success} at={now:O}";
            notified++;
        }

        await _db.SaveChangesAsync(ct);
        _logger.LogInformation(
            "[SOAR] Approval-timeout sweep: stale={Stale} notified={Notified} auto_rejected={Rejected}",
            staleApprovals.Count, notified, autoRejected);
    }

    private static string BuildEscalationHtml(string playbookName, string alertTitle, string severity, double ageMinutes) => $$"""
        <!DOCTYPE html><html><body style="font-family:Segoe UI,Arial,sans-serif;background:#0b1320;color:#e8edf5;padding:24px;">
          <div style="max-width:600px;margin:0 auto;background:#101a2e;border:1px solid #f59e0b;border-radius:10px;padding:24px;">
            <h2 style="margin:0 0 12px 0;color:#f59e0b;">⚠ Pending SOAR approval timing out</h2>
            <p style="margin:0 0 8px 0;">Playbook <strong>{{playbookName}}</strong> has been waiting for approval for <strong>{{ageMinutes:F0}} minutes</strong>.</p>
            <p style="margin:0 0 16px 0;color:#a3b1c6;">Triggered by alert: <em>{{alertTitle}}</em> ({{severity}}).</p>
            <p style="margin:0;color:#a3b1c6;font-size:13px;">Open the SOC dashboard → Playbooks → Pending Approvals to action this.</p>
          </div>
        </body></html>
        """;
}
