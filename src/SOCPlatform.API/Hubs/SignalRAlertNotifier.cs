using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;

namespace SOCPlatform.API.Hubs;

/// <summary>
/// IAlertNotifier backed by SignalR + Redis backplane. Emits to every connected
/// client on every API replica (the backplane relays through Redis pub/sub).
/// Handles exceptions internally so a failed broadcast never blocks the
/// detection pipeline.
/// </summary>
public sealed class SignalRAlertNotifier : IAlertNotifier
{
    private readonly IHubContext<AlertHub> _hub;
    private readonly ILogger<SignalRAlertNotifier> _logger;

    public SignalRAlertNotifier(IHubContext<AlertHub> hub, ILogger<SignalRAlertNotifier> logger)
    {
        _hub = hub;
        _logger = logger;
    }

    public async Task BroadcastAlertAsync(Alert alert, CancellationToken ct = default)
    {
        try
        {
            await _hub.Clients.All.SendAsync(AlertHub.Events.AlertNew, ToDto(alert), ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[SignalR] failed to broadcast alert {AlertId}", alert.Id);
        }
    }

    public async Task BroadcastAlertsAsync(IReadOnlyList<Alert> alerts, CancellationToken ct = default)
    {
        if (alerts.Count == 0) return;
        try
        {
            // One batch message instead of N individual ones — cheaper over the backplane.
            await _hub.Clients.All.SendAsync(AlertHub.Events.AlertBatch,
                new { alerts = alerts.Select(ToDto).ToArray() }, ct);
            _logger.LogDebug("[SignalR] broadcast {Count} alerts", alerts.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[SignalR] failed to broadcast {Count} alerts", alerts.Count);
        }
    }

    private static object ToDto(Alert a) => new
    {
        id = a.Id,
        title = a.Title,
        description = a.Description,
        severity = a.Severity.ToString(),
        status = a.Status.ToString(),
        sourceIp = a.SourceIP,
        affectedUser = a.AffectedUser,
        affectedDevice = a.AffectedDevice,
        detectionRuleName = a.DetectionRuleName,
        mitreTechnique = a.MitreTechnique,
        mitreTactic = a.MitreTactic,
        createdAt = a.CreatedAt,
        slaDeadline = a.SlaDeadline
    };
}
