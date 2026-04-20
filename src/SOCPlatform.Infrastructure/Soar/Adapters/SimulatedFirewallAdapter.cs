using SOCPlatform.Core.Soar;

namespace SOCPlatform.Infrastructure.Soar.Adapters;

/// <summary>
/// Simulated firewall — pretends to be pfSense/Palo Alto for demo purposes.
/// Logs every block/unblock to SimulatedActionLog with realistic latency.
/// </summary>
public sealed class SimulatedFirewallAdapter : IFirewallAdapter
{
    public string Name => nameof(SimulatedFirewallAdapter);
    public bool IsSimulated => true;

    private readonly SimulatedActionRecorder _recorder;

    public SimulatedFirewallAdapter(SimulatedActionRecorder recorder) => _recorder = recorder;

    public Task<AdapterResult> BlockIpAsync(string ipAddress, string reason, Guid? alertId, CancellationToken ct = default) =>
        _recorder.RecordAsync(Name, "BlockIp", ipAddress, reason, alertId, () =>
        {
            // In real life, this is where we'd call the firewall vendor's REST API.
            return Task.FromResult<(bool, string, Dictionary<string, object>?, string?)>((
                true,
                $"IP {ipAddress} added to perimeter blocklist",
                new() { ["rule_name"] = $"sentinelops-{ipAddress}", ["ttl_seconds"] = 86400 },
                null));
        }, ct);

    public Task<AdapterResult> UnblockIpAsync(string ipAddress, string reason, Guid? alertId, CancellationToken ct = default) =>
        _recorder.RecordAsync(Name, "UnblockIp", ipAddress, reason, alertId, () =>
            Task.FromResult<(bool, string, Dictionary<string, object>?, string?)>((
                true,
                $"IP {ipAddress} removed from perimeter blocklist",
                null, null)),
            ct);
}
