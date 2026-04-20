using System.Text.Json;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Core.Soar;

namespace SOCPlatform.Detection.Playbooks;

/// <summary>
/// Shared utility — wraps an adapter call so that every SOAR action emits a
/// uniform entry into the hash-chained audit log (forensics + tamper-evidence).
/// </summary>
internal static class SoarAuditExtensions
{
    public static async Task AuditAsync(this IAuditService audit, AdapterResult result, Alert alert, string action)
    {
        await audit.LogAsync(
            userId: null,
            action: $"SOAR.{action}",
            resource: "Alert",
            resourceId: alert.Id.ToString(),
            details: $"adapter={result.AdapterName} simulated={result.IsSimulated} target={result.Target} success={result.Success} latency={result.LatencyMs}ms",
            newValue: JsonSerializer.Serialize(new
            {
                adapter = result.AdapterName,
                simulated = result.IsSimulated,
                action = result.Action,
                target = result.Target,
                success = result.Success,
                message = result.Message,
                latencyMs = result.LatencyMs,
                metadata = result.Metadata,
                error = result.ErrorDetail
            }));
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Existing 4 actions — now thin orchestrators that delegate to adapters
// ════════════════════════════════════════════════════════════════════════════

public sealed class BlockIpAction : IPlaybookAction
{
    public PlaybookActionType ActionType => PlaybookActionType.BlockIp;

    private readonly IFirewallAdapter _firewall;
    private readonly IAuditService _audit;
    private readonly ILogger<BlockIpAction> _logger;

    public BlockIpAction(IFirewallAdapter firewall, IAuditService audit, ILogger<BlockIpAction> logger)
    {
        _firewall = firewall;
        _audit = audit;
        _logger = logger;
    }

    public async Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(alert.SourceIP))
            return "No source IP to block — skipped";

        var reason = $"{alert.Title} ({alert.DetectionRuleName})";
        var result = await _firewall.BlockIpAsync(alert.SourceIP, reason, alert.Id, ct);
        await _audit.AuditAsync(result, alert, "BlockIp");

        _logger.LogWarning("[SOAR] BlockIp via {Adapter} target={IP} success={Success}", result.AdapterName, alert.SourceIP, result.Success);
        return $"[{(result.IsSimulated ? "SIM" : "REAL")} · {result.AdapterName}] {result.Message}";
    }
}

public sealed class LockAccountAction : IPlaybookAction
{
    public PlaybookActionType ActionType => PlaybookActionType.LockAccount;

    private readonly IIdentityAdapter _identity;
    private readonly IAuditService _audit;
    private readonly ILogger<LockAccountAction> _logger;

    public LockAccountAction(IIdentityAdapter identity, IAuditService audit, ILogger<LockAccountAction> logger)
    {
        _identity = identity;
        _audit = audit;
        _logger = logger;
    }

    public async Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(alert.AffectedUser))
            return "No affected user to lock — skipped";

        var minutes = 30;
        if (!string.IsNullOrEmpty(actionConfig) && int.TryParse(actionConfig, out var configured)) minutes = configured;

        var reason = $"{alert.Title} ({alert.DetectionRuleName})";
        var result = await _identity.LockAccountAsync(alert.AffectedUser, TimeSpan.FromMinutes(minutes), reason, alert.Id, ct);
        await _audit.AuditAsync(result, alert, "LockAccount");

        _logger.LogWarning("[SOAR] LockAccount via {Adapter} user={User} duration={Min}m", result.AdapterName, alert.AffectedUser, minutes);
        return $"[{(result.IsSimulated ? "SIM" : "REAL")} · {result.AdapterName}] {result.Message}";
    }
}

public sealed class NotifyManagerAction : IPlaybookAction
{
    public PlaybookActionType ActionType => PlaybookActionType.NotifyManager;

    private readonly INotificationAdapter _notify;
    private readonly IAuditService _audit;
    private readonly ILogger<NotifyManagerAction> _logger;

    public NotifyManagerAction(INotificationAdapter notify, IAuditService audit, ILogger<NotifyManagerAction> logger)
    {
        _notify = notify;
        _audit = audit;
        _logger = logger;
    }

    public async Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        var html = BuildAlertEmailHtml(alert);
        var text = BuildAlertEmailText(alert);

        var request = new NotificationRequest(
            Subject: $"{alert.Severity} alert: {alert.Title}",
            HtmlBody: html,
            PlainTextBody: text,
            Severity: alert.Severity.ToString(),
            AlertId: alert.Id,
            Recipient: actionConfig); // optional override from playbook config

        var result = await _notify.NotifyAsync(request, ct);
        await _audit.AuditAsync(result, alert, "NotifyManager");

        _logger.LogWarning("[SOAR] NotifyManager via {Adapter} alert={Alert} success={Success}", result.AdapterName, alert.Title, result.Success);
        return $"[{result.AdapterName}] {result.Message}";
    }

    private static string BuildAlertEmailHtml(Alert alert) => $$"""
        <!DOCTYPE html><html><body style="font-family:Segoe UI,Arial,sans-serif;background:#0b1320;color:#e8edf5;padding:24px;">
          <div style="max-width:600px;margin:0 auto;background:#101a2e;border:1px solid #1f2c44;border-radius:10px;padding:24px;">
            <h2 style="margin:0 0 12px 0;color:#f87171;">SentinelOps · {{alert.Severity}} Alert</h2>
            <h3 style="margin:0 0 16px 0;color:#5fb4ff;">{{alert.Title}}</h3>
            <p style="color:#a3b1c6;font-size:13px;margin:0 0 16px 0;">{{alert.Description}}</p>
            <table style="width:100%;font-size:13px;color:#e8edf5;">
              <tr><td style="color:#a3b1c6;width:130px;">Rule:</td><td>{{alert.DetectionRuleName}}</td></tr>
              <tr><td style="color:#a3b1c6;">MITRE:</td><td>{{alert.MitreTechnique}} · {{alert.MitreTactic}}</td></tr>
              <tr><td style="color:#a3b1c6;">Source IP:</td><td>{{alert.SourceIP ?? "n/a"}}</td></tr>
              <tr><td style="color:#a3b1c6;">Affected user:</td><td>{{alert.AffectedUser ?? "n/a"}}</td></tr>
              <tr><td style="color:#a3b1c6;">Affected device:</td><td>{{alert.AffectedDevice ?? "n/a"}}</td></tr>
              <tr><td style="color:#a3b1c6;">SLA deadline:</td><td>{{alert.SlaDeadline:u}}</td></tr>
            </table>
          </div>
          <p style="text-align:center;color:#6b7a93;font-size:11px;margin-top:18px;">
            SentinelOps SOC · automated SOAR notification
          </p>
        </body></html>
        """;

    private static string BuildAlertEmailText(Alert alert) =>
        $"SentinelOps · {alert.Severity} alert\n\n" +
        $"{alert.Title}\n{alert.Description}\n\n" +
        $"Rule: {alert.DetectionRuleName}\n" +
        $"MITRE: {alert.MitreTechnique} · {alert.MitreTactic}\n" +
        $"Source IP: {alert.SourceIP ?? "n/a"}\n" +
        $"Affected user: {alert.AffectedUser ?? "n/a"}\n" +
        $"Affected device: {alert.AffectedDevice ?? "n/a"}\n" +
        $"SLA deadline: {alert.SlaDeadline:u}\n";
}

/// <summary>
/// Pure local-DB action — no external adapter. Just audited.
/// </summary>
public sealed class EscalateAlertAction : IPlaybookAction
{
    public PlaybookActionType ActionType => PlaybookActionType.EscalateAlert;

    private readonly IAuditService _audit;
    private readonly ILogger<EscalateAlertAction> _logger;

    public EscalateAlertAction(IAuditService audit, ILogger<EscalateAlertAction> logger)
    {
        _audit = audit;
        _logger = logger;
    }

    public async Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        var prev = alert.Status;
        alert.Status = AlertStatus.Escalated;
        alert.UpdatedAt = DateTime.UtcNow;

        await _audit.LogAsync(
            userId: null, action: "SOAR.EscalateAlert", resource: "Alert", resourceId: alert.Id.ToString(),
            oldValue: prev.ToString(), newValue: AlertStatus.Escalated.ToString(),
            details: $"Auto-escalated by SOAR: {alert.Title}");

        _logger.LogWarning("[SOAR] EscalateAlert id={Id} {Old}→{New}", alert.Id, prev, alert.Status);
        return $"Alert '{alert.Title}' escalated from {prev} to Escalated";
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  3 NEW actions — IsolateEndpoint, DisableUser, ResetCredentials
// ════════════════════════════════════════════════════════════════════════════

public sealed class IsolateEndpointAction : IPlaybookAction
{
    public PlaybookActionType ActionType => PlaybookActionType.IsolateEndpoint;

    private readonly IEndpointAdapter _endpoint;
    private readonly IAuditService _audit;
    private readonly ILogger<IsolateEndpointAction> _logger;

    public IsolateEndpointAction(IEndpointAdapter endpoint, IAuditService audit, ILogger<IsolateEndpointAction> logger)
    {
        _endpoint = endpoint;
        _audit = audit;
        _logger = logger;
    }

    public async Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(alert.AffectedDevice))
            return "No affected device to isolate — skipped";

        var reason = $"{alert.Title} ({alert.DetectionRuleName})";
        var result = await _endpoint.IsolateEndpointAsync(alert.AffectedDevice, reason, alert.Id, ct);
        await _audit.AuditAsync(result, alert, "IsolateEndpoint");

        _logger.LogWarning("[SOAR] IsolateEndpoint via {Adapter} host={Host}", result.AdapterName, alert.AffectedDevice);
        return $"[{(result.IsSimulated ? "SIM" : "REAL")} · {result.AdapterName}] {result.Message}";
    }
}

public sealed class DisableUserAction : IPlaybookAction
{
    public PlaybookActionType ActionType => PlaybookActionType.DisableUser;

    private readonly IIdentityAdapter _identity;
    private readonly IAuditService _audit;
    private readonly ILogger<DisableUserAction> _logger;

    public DisableUserAction(IIdentityAdapter identity, IAuditService audit, ILogger<DisableUserAction> logger)
    {
        _identity = identity;
        _audit = audit;
        _logger = logger;
    }

    public async Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(alert.AffectedUser))
            return "No affected user to disable — skipped";

        var reason = $"{alert.Title} ({alert.DetectionRuleName})";
        var result = await _identity.DisableUserAsync(alert.AffectedUser, reason, alert.Id, ct);
        await _audit.AuditAsync(result, alert, "DisableUser");

        _logger.LogWarning("[SOAR] DisableUser via {Adapter} user={User}", result.AdapterName, alert.AffectedUser);
        return $"[{(result.IsSimulated ? "SIM" : "REAL")} · {result.AdapterName}] {result.Message}";
    }
}

public sealed class ResetCredentialsAction : IPlaybookAction
{
    public PlaybookActionType ActionType => PlaybookActionType.ResetCredentials;

    private readonly IIdentityAdapter _identity;
    private readonly IAuditService _audit;
    private readonly ILogger<ResetCredentialsAction> _logger;

    public ResetCredentialsAction(IIdentityAdapter identity, IAuditService audit, ILogger<ResetCredentialsAction> logger)
    {
        _identity = identity;
        _audit = audit;
        _logger = logger;
    }

    public async Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(alert.AffectedUser))
            return "No affected user to reset — skipped";

        var reason = $"{alert.Title} ({alert.DetectionRuleName})";
        var result = await _identity.ResetCredentialsAsync(alert.AffectedUser, reason, alert.Id, ct);
        await _audit.AuditAsync(result, alert, "ResetCredentials");

        _logger.LogWarning("[SOAR] ResetCredentials via {Adapter} user={User}", result.AdapterName, alert.AffectedUser);
        return $"[{(result.IsSimulated ? "SIM" : "REAL")} · {result.AdapterName}] {result.Message}";
    }
}
