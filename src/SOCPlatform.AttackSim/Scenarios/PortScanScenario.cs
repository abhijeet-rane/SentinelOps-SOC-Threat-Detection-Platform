using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>25 distinct destination-port connections from one source in 40 s → PortScanRule.</summary>
public sealed class PortScanScenario : IAttackScenario
{
    public string Name => "port-scan";
    public string Description => "25 distinct ports probed from one IP (network recon) — T1046";
    public string[] ExpectedRules => ["Port Scan Detection"];

    public List<SyntheticSecurityEventDto> Build()
    {
        const string srcIp = "198.51.100.23";
        const string dstIp = "10.0.0.50";
        // Anchored to NOW so the DetectionEngine watermark always picks up the batch.
        // 100 ms spacing → 25 events span 2.4 s, well inside PortScan's 60 s window.
        var now = DateTime.UtcNow;
        var ports = new[] { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587,
                            993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 9200 };

        return ports.Select((p, i) => new SyntheticSecurityEventDto
        {
            EventCategory   = "Network",
            EventAction     = "ActiveConnections",   // matches PortScanRule filter
            Severity        = "Low",
            SourceIP        = srcIp,
            DestinationIP   = dstIp,
            DestinationPort = p,
            MitreTechnique  = "T1046",
            MitreTactic     = "Discovery",
            Timestamp       = now.AddMilliseconds(i * 100),
        }).ToList();
    }
}
