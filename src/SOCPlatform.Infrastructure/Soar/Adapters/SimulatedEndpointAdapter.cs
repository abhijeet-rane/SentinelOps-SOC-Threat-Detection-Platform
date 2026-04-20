using SOCPlatform.Core.Soar;

namespace SOCPlatform.Infrastructure.Soar.Adapters;

/// <summary>
/// Simulated endpoint isolation. Real impls would call CrowdStrike RTR /
/// SentinelOne / Defender for Endpoint. This one just records the action.
/// </summary>
public sealed class SimulatedEndpointAdapter : IEndpointAdapter
{
    public string Name => nameof(SimulatedEndpointAdapter);
    public bool IsSimulated => true;

    private readonly SimulatedActionRecorder _recorder;

    public SimulatedEndpointAdapter(SimulatedActionRecorder recorder) => _recorder = recorder;

    public Task<AdapterResult> IsolateEndpointAsync(string hostname, string reason, Guid? alertId, CancellationToken ct = default) =>
        _recorder.RecordAsync(Name, "IsolateEndpoint", hostname, reason, alertId, () =>
            Task.FromResult<(bool, string, Dictionary<string, object>?, string?)>((
                true,
                $"Endpoint '{hostname}' quarantined — only management VLAN reachable",
                new() { ["isolation_mode"] = "network", ["allowed_vlan"] = "MGMT" },
                null)),
            ct);

    public Task<AdapterResult> UnisolateEndpointAsync(string hostname, string reason, Guid? alertId, CancellationToken ct = default) =>
        _recorder.RecordAsync(Name, "UnisolateEndpoint", hostname, reason, alertId, () =>
            Task.FromResult<(bool, string, Dictionary<string, object>?, string?)>((
                true,
                $"Endpoint '{hostname}' isolation lifted — back on production network",
                null, null)),
            ct);
}
