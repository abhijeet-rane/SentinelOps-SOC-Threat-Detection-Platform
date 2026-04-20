namespace SOCPlatform.Core.Soar;

/// <summary>
/// Firewall integration: add/remove IPs from the perimeter blocklist.
/// Real implementations: pfSense REST · Palo Alto XML API · AWS WAF · Cloudflare.
/// Default in this build is the simulator (writes to SimulatedActionLog).
/// </summary>
public interface IFirewallAdapter
{
    /// <summary>Display name of the backing target ("pfSense", "Simulated", …).</summary>
    string Name { get; }

    /// <summary>True if this adapter is the simulator (drives UI "Simulated" badge).</summary>
    bool IsSimulated { get; }

    Task<AdapterResult> BlockIpAsync(string ipAddress, string reason, Guid? alertId, CancellationToken ct = default);

    Task<AdapterResult> UnblockIpAsync(string ipAddress, string reason, Guid? alertId, CancellationToken ct = default);
}
