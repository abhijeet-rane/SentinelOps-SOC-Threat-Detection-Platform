namespace SOCPlatform.Core.Entities;

/// <summary>
/// Append-only log of every simulated SOAR action executed by a "Simulated*"
/// adapter. Real adapter calls don't write here (their effect is visible in
/// the target system itself). The Audit Log table still captures every adapter
/// call regardless of simulator vs real.
/// Also drives the dashboard "Simulated" badge — analysts can scroll the
/// timeline of simulated actions per alert / hostname / IP.
/// </summary>
public class SimulatedActionLog
{
    public long Id { get; set; }

    /// <summary>e.g. "SimulatedFirewallAdapter".</summary>
    public string AdapterName { get; set; } = string.Empty;

    /// <summary>e.g. "BlockIp", "IsolateEndpoint", "DisableUser".</summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>The target of the action (IP / username / hostname).</summary>
    public string Target { get; set; } = string.Empty;

    /// <summary>Free-form reason captured at call time.</summary>
    public string? Reason { get; set; }

    /// <summary>JSON snapshot of the request/response context (for forensics).</summary>
    public string? Payload { get; set; }

    public bool Success { get; set; }
    public string? ErrorDetail { get; set; }

    /// <summary>Simulated network latency (ms) — adapters add 50-200 ms by design.</summary>
    public int LatencyMs { get; set; }

    public DateTime ExecutedAt { get; set; } = DateTime.UtcNow;

    /// <summary>FK back to the alert that triggered the action, when applicable.</summary>
    public Guid? AlertId { get; set; }
}
