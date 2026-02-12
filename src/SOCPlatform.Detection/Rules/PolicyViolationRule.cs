using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules;

/// <summary>
/// Detects policy violations: access to restricted resources.
/// MITRE ATT&CK: T1078 – Valid Accounts (Defense Evasion)
/// </summary>
public class PolicyViolationRule : IDetectionRule
{
    public string Name => "Policy Violation – Restricted Resource";
    public string MitreTechnique => "T1078";
    public string MitreTactic => "Defense Evasion";
    public string Severity => "Medium";
    public bool IsEnabled { get; set; } = true;

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var violations = events
            .Where(e => e.EventAction == "FileAccess" && e.EventCategory == "Security")
            .ToList();

        foreach (var ev in violations)
        {
            alerts.Add(new Alert
            {
                Title = $"Policy Violation – {ev.AffectedUser} accessed restricted resource",
                Description = $"User '{ev.AffectedUser}' accessed a restricted resource on device '{ev.AffectedDevice}'. " +
                              $"Source IP: {ev.SourceIP}.",
                Severity = Core.Enums.Severity.Medium,
                DetectionRuleName = Name,
                MitreTechnique = MitreTechnique,
                MitreTactic = MitreTactic,
                AffectedUser = ev.AffectedUser,
                AffectedDevice = ev.AffectedDevice,
                SourceIP = ev.SourceIP,
                EventId = ev.Id,
                RecommendedAction = "Review access patterns, verify authorization, update access policies"
            });
        }

        return Task.FromResult(alerts);
    }
}
