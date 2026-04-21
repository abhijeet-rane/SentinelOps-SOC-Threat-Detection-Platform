using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>
/// 12 outbound connections at near-constant 60 s intervals with &lt; 0.2 jitter →
/// C2BeaconingRule. Uses Cobalt Strike's default 60-second sleep.
/// </summary>
public sealed class C2BeaconScenario : IAttackScenario
{
    public string Name => "c2-beacon";
    public string Description => "Periodic 60 s outbound beacon — T1071";
    public string[] ExpectedRules => ["C2 Beaconing"];

    public List<SyntheticSecurityEventDto> Build()
    {
        const string srcIp = "10.0.0.42";
        const string dstIp = "185.220.101.42"; // classic Tor exit node from seed data
        var now = DateTime.UtcNow;
        var rng = new Random(13);

        // Compressed beacon: 500 ms ± 40 ms (jitter ratio ≈ 0.05 — well under 0.2
        // threshold). The C2BeaconingRule only checks stddev/mean of intervals,
        // not the absolute period, so demo results are the same as a real 60 s beacon.
        return Enumerable.Range(0, 12).Select(i => new SyntheticSecurityEventDto
        {
            EventCategory   = "Network",
            EventAction     = "NetworkConnection",
            Severity        = "Medium",
            SourceIP        = srcIp,
            DestinationIP   = dstIp,
            DestinationPort = 443,
            AffectedDevice  = "WRK-042",
            MitreTechnique  = "T1071",
            MitreTactic     = "Command and Control",
            Timestamp       = now.AddMilliseconds(i * 500 + (rng.NextDouble() * 80 - 40)),
        }).ToList();
    }
}
