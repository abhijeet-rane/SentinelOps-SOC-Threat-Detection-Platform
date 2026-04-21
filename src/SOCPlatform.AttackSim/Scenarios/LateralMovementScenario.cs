using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>Same user successfully logs into 4 distinct hosts in 12 minutes → LateralMovementRule.</summary>
public sealed class LateralMovementScenario : IAttackScenario
{
    public string Name => "lateral";
    public string Description => "Single user hops across 4 hosts in 12 min (post-breach) — T1021";
    public string[] ExpectedRules => ["Lateral Movement"];

    public List<SyntheticSecurityEventDto> Build()
    {
        const string user = "alice";
        var hosts = new[] { "WRK-01", "SVR-DB-01", "SVR-FILE-01", "SVR-DC-01" };
        var now = DateTime.UtcNow;

        // Rule checks distinct hosts inside a 30-min sliding window — 400 ms spacing
        // keeps everything inside the window without aging events out of the DetectionEngine cycle.
        return hosts.Select((h, i) => new SyntheticSecurityEventDto
        {
            EventCategory   = "Authentication",
            EventAction     = "LoginSuccess",
            Severity        = "Low",
            SourceIP        = "10.0.0.5",
            AffectedUser    = user,
            AffectedDevice  = h,
            MitreTechnique  = "T1021",
            MitreTactic     = "Lateral Movement",
            Timestamp       = now.AddMilliseconds(i * 400),
        }).ToList();
    }
}
