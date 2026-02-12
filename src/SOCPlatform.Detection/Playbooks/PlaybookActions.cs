using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Playbooks;

/// <summary>
/// IP Block Playbook – logs the offending IP to a blocklist table.
/// In production, this would integrate with a firewall API (e.g., Palo Alto, AWS WAF).
/// </summary>
public class BlockIpAction : IPlaybookAction
{
    private readonly ILogger<BlockIpAction> _logger;

    public PlaybookActionType ActionType => PlaybookActionType.BlockIp;

    public BlockIpAction(ILogger<BlockIpAction> logger)
    {
        _logger = logger;
    }

    public Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(alert.SourceIP))
            return Task.FromResult("No source IP to block — skipped");

        _logger.LogWarning("🔒 SOAR: Blocking IP {IP} (Alert: {AlertTitle})", alert.SourceIP, alert.Title);

        // In production: call firewall API, update WAF rules, add to network blocklist
        // For now: log the action for audit trail
        var result = $"IP {alert.SourceIP} added to blocklist. Reason: {alert.Title} ({alert.DetectionRuleName})";

        return Task.FromResult(result);
    }
}

/// <summary>
/// Account Lockout Playbook – flags an account for temporary lockout.
/// </summary>
public class LockAccountAction : IPlaybookAction
{
    private readonly ILogger<LockAccountAction> _logger;

    public PlaybookActionType ActionType => PlaybookActionType.LockAccount;

    public LockAccountAction(ILogger<LockAccountAction> logger)
    {
        _logger = logger;
    }

    public Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(alert.AffectedUser))
            return Task.FromResult("No affected user to lock — skipped");

        var lockDurationMinutes = 30; // Default 30 minutes
        if (!string.IsNullOrEmpty(actionConfig) && int.TryParse(actionConfig, out var minutes))
            lockDurationMinutes = minutes;

        _logger.LogWarning("🔒 SOAR: Locking account '{User}' for {Duration}m (Alert: {AlertTitle})",
            alert.AffectedUser, lockDurationMinutes, alert.Title);

        // In production: update user record with LockoutEnd, disable AD account
        var result = $"Account '{alert.AffectedUser}' flagged for {lockDurationMinutes}-minute lockout. Reason: {alert.Title}";

        return Task.FromResult(result);
    }
}

/// <summary>
/// Notification Playbook – sends notification to SOC Manager.
/// </summary>
public class NotifyManagerAction : IPlaybookAction
{
    private readonly ILogger<NotifyManagerAction> _logger;

    public PlaybookActionType ActionType => PlaybookActionType.NotifyManager;

    public NotifyManagerAction(ILogger<NotifyManagerAction> logger)
    {
        _logger = logger;
    }

    public Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        _logger.LogWarning("📧 SOAR: Notifying SOC Manager — {Severity} alert: {AlertTitle}",
            alert.Severity, alert.Title);

        // In production: send email, Slack message, Teams notification, PagerDuty alert
        var result = $"SOC Manager notified of {alert.Severity} alert: {alert.Title}. " +
                     $"Affected: {alert.AffectedUser ?? alert.SourceIP ?? "N/A"}";

        return Task.FromResult(result);
    }
}

/// <summary>
/// Escalation Playbook – auto-escalates the alert based on severity thresholds.
/// </summary>
public class EscalateAlertAction : IPlaybookAction
{
    private readonly ILogger<EscalateAlertAction> _logger;

    public PlaybookActionType ActionType => PlaybookActionType.EscalateAlert;

    public EscalateAlertAction(ILogger<EscalateAlertAction> logger)
    {
        _logger = logger;
    }

    public Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        _logger.LogWarning("⬆️ SOAR: Auto-escalating alert '{AlertTitle}' (Severity: {Severity})",
            alert.Title, alert.Severity);

        // Escalate the alert status
        alert.Status = AlertStatus.Escalated;
        alert.UpdatedAt = DateTime.UtcNow;

        var result = $"Alert '{alert.Title}' escalated to Escalated status. Severity: {alert.Severity}";

        return Task.FromResult(result);
    }
}
