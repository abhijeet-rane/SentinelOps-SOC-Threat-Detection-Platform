using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>High-entropy / oversized DNS subdomains → DnsTunnelingRule.</summary>
public sealed class DnsTunnelScenario : IAttackScenario
{
    public string Name => "dns-tunnel";
    public string Description => "Encoded data in DNS subdomains (base32-style) — T1572";
    public string[] ExpectedRules => ["DNS Tunneling"];

    public List<SyntheticSecurityEventDto> Build()
    {
        var chunks = new[]
        {
            "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",  // high-entropy label
            "Zx9kL3qXp7vRnMyWoP2sHk5tYbN4vCa8rDuGhJ9q",
            "aGVsbG9fbXlfbmFtZV9pc19zZW50aW5lbG9wc19leGZpbA"  // base64 long
        };
        var parent = "tunnel.attacker-c2.example";
        // Anchored to NOW so the DetectionEngine watermark always picks up the batch.
        var now = DateTime.UtcNow;

        return chunks.Select((c, i) => new SyntheticSecurityEventDto
        {
            EventCategory  = "Network",
            EventAction    = "DnsQuery",
            Severity       = "Low",
            SourceIP       = "10.0.0.77",
            AffectedDevice = "WRK-077",
            MitreTechnique = "T1572",
            MitreTactic    = "Command and Control",
            Metadata       = new Dictionary<string, object?> { ["domain"] = $"{c}.{parent}" },
            Timestamp      = now.AddMilliseconds(i * 200),
        }).ToList();
    }
}
