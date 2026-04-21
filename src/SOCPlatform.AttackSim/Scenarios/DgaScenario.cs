using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>DNS queries to algorithmically-generated-looking domains → DgaDetectionRule.</summary>
public sealed class DgaScenario : IAttackScenario
{
    public string Name => "dga";
    public string Description => "DNS queries to DGA-looking domains (Conficker / Necurs style) — T1568.002";
    public string[] ExpectedRules => ["DGA Domain Detection"];

    public List<SyntheticSecurityEventDto> Build()
    {
        // Deliberately gibberish second-level labels — will score below the -6.3 bigram threshold.
        var domains = new[]
        {
            "kq1zxqbgwvjx.top",
            "qzjxwvnmpfbkyh.biz",
            "xkqzvmpnfbwj.info",
            "zxczxvbvnbmpq.xyz",
            "pplkjhgfdsaqw.top",
            "bnmvcxzlkjhgf.biz"
        };
        var now = DateTime.UtcNow;

        return domains.Select((d, i) => new SyntheticSecurityEventDto
        {
            EventCategory  = "Network",
            EventAction    = "DnsQuery",
            Severity       = "Low",
            SourceIP       = "10.0.0.55",
            AffectedDevice = "WRK-055",
            MitreTechnique = "T1568.002",
            MitreTactic    = "Command and Control",
            Metadata       = new Dictionary<string, object?> { ["domain"] = d },
            Timestamp      = now.AddMilliseconds(i * 200),
        }).ToList();
    }
}
