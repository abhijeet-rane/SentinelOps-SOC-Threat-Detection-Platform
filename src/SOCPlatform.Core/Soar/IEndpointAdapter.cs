namespace SOCPlatform.Core.Soar;

/// <summary>
/// Endpoint network-isolation. Real implementations: CrowdStrike RTR · SentinelOne · Defender for Endpoint.
/// </summary>
public interface IEndpointAdapter
{
    string Name { get; }
    bool IsSimulated { get; }

    /// <summary>Quarantine a host from the network (allow only management VLAN).</summary>
    Task<AdapterResult> IsolateEndpointAsync(string hostname, string reason, Guid? alertId, CancellationToken ct = default);

    /// <summary>Lift the network-isolation quarantine.</summary>
    Task<AdapterResult> UnisolateEndpointAsync(string hostname, string reason, Guid? alertId, CancellationToken ct = default);
}
