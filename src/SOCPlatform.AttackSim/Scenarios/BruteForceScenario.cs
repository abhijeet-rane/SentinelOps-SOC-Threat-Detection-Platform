using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>10 failed logins from the same IP in 90 seconds → BruteForceRule.</summary>
public sealed class BruteForceScenario : IAttackScenario
{
    public string Name => "brute-force";
    public string Description => "10 failed logins from one IP (credential stuffing) — T1110";
    public string[] ExpectedRules => ["Brute Force Detection"];

    public List<SyntheticSecurityEventDto> Build()
    {
        const string srcIp = "203.0.113.77";
        var users = new[] { "admin", "root", "administrator", "soc.manager", "analyst.l1", "test", "backup", "svc" };
        // Anchor to NOW so the DetectionEngine's incremental timestamp filter
        // (Timestamp >= _lastEvaluationTime) always picks up the batch.
        var now = DateTime.UtcNow;

        return Enumerable.Range(0, 10).Select(i => new SyntheticSecurityEventDto
        {
            EventCategory   = "Authentication",
            EventAction     = "LoginFailure",
            Severity        = "Medium",
            SourceIP        = srcIp,
            AffectedUser    = users[i % users.Length],
            AffectedDevice  = "DC-01",
            MitreTechnique  = "T1110",
            MitreTactic     = "Credential Access",
            // 300 ms apart — 10 events cover 2.7 s, well inside BruteForce's 5-min window
            Timestamp       = now.AddMilliseconds(i * 300),
        }).ToList();
    }
}
