using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>SpecialPrivilegeAssigned outside business hours → PrivilegeEscalationRule.</summary>
public sealed class PrivEscScenario : IAttackScenario
{
    public string Name => "priv-esc";
    public string Description => "Special privilege assigned outside business hours — T1078";
    // Must match PrivilegeEscalationRule.Name verbatim — that's what
    // ends up in Alert.DetectionRuleName for the simulator's poll loop.
    public string[] ExpectedRules => ["Privilege Escalation (Unusual Hours)"];

    public List<SyntheticSecurityEventDto> Build()
    {
        // PrivilegeEscalationRule converts Timestamp to local time before
        // comparing against 08:00-18:00. Using 23:17 LOCAL today guarantees
        // the event is off-hours regardless of the server's timezone.
        var offHoursLocal = DateTime.Now.Date.AddHours(23).AddMinutes(17);
        var offHours      = offHoursLocal.ToUniversalTime();

        return new List<SyntheticSecurityEventDto>
        {
            new()
            {
                EventCategory  = "Security",
                EventAction    = "SpecialPrivilegeAssigned",
                Severity       = "High",
                AffectedUser   = "bob",
                AffectedDevice = "DC-01",
                SourceIP       = "10.0.0.88",
                MitreTechnique = "T1078",
                MitreTactic    = "Privilege Escalation",
                Timestamp      = offHours,
            }
        };
    }
}
