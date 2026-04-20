using SOCPlatform.Core.Entities;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Pushes newly-created alerts to connected SOC analysts in real time.
/// Default implementation broadcasts over SignalR with a Redis backplane so
/// every API instance can notify every connected client.
/// A NullAlertNotifier is used in tests so detection tests don't require a hub.
/// </summary>
public interface IAlertNotifier
{
    /// <summary>Broadcast a single newly-persisted alert to every subscribed client.</summary>
    Task BroadcastAlertAsync(Alert alert, CancellationToken ct = default);

    /// <summary>Broadcast a batch of alerts in one round-trip (preferred from DetectionEngine).</summary>
    Task BroadcastAlertsAsync(IReadOnlyList<Alert> alerts, CancellationToken ct = default);
}

/// <summary>
/// No-op implementation used when SignalR is unavailable (tests, offline mode).
/// Safe to register as a fallback so detection code can always call the notifier.
/// </summary>
public sealed class NullAlertNotifier : IAlertNotifier
{
    public Task BroadcastAlertAsync(Alert alert, CancellationToken ct = default) => Task.CompletedTask;
    public Task BroadcastAlertsAsync(IReadOnlyList<Alert> alerts, CancellationToken ct = default) => Task.CompletedTask;
}
