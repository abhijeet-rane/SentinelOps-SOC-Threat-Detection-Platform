using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules;

/// <summary>
/// Detects privilege escalation: admin/elevated access at unusual hours (outside 08:00–18:00 local).
/// MITRE ATT&CK: T1078 – Valid Accounts (Privilege Escalation)
/// </summary>
public class PrivilegeEscalationRule : IDetectionRule
{
    public string Name => "Privilege Escalation (Unusual Hours)";
    public string MitreTechnique => "T1078";
    public string MitreTactic => "Privilege Escalation";
    public string Severity => "Critical";
    public bool IsEnabled { get; set; } = true;

    private readonly TimeSpan _businessStart = new(8, 0, 0);
    private readonly TimeSpan _businessEnd = new(18, 0, 0);

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var privilegeEvents = events
            .Where(e => e.EventAction is "SpecialPrivilegeAssigned" or "SensitivePrivilegeUse")
            .ToList();

        foreach (var ev in privilegeEvents)
        {
            var localTime = ev.Timestamp.ToLocalTime().TimeOfDay;
            if (localTime < _businessStart || localTime > _businessEnd)
            {
                alerts.Add(new Alert
                {
                    Title = $"Privilege Escalation Outside Business Hours – {ev.AffectedUser}",
                    Description = $"User '{ev.AffectedUser}' performed '{ev.EventAction}' at {ev.Timestamp:HH:mm} UTC " +
                                  $"(outside 08:00–18:00 business hours) on device '{ev.AffectedDevice}'.",
                    Severity = Core.Enums.Severity.Critical,
                    DetectionRuleName = Name,
                    MitreTechnique = MitreTechnique,
                    MitreTactic = MitreTactic,
                    AffectedUser = ev.AffectedUser,
                    AffectedDevice = ev.AffectedDevice,
                    EventId = ev.Id,
                    RecommendedAction = "Verify with the user, check for lateral movement, review session logs"
                });
            }
        }

        return Task.FromResult(alerts);
    }
}
