using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules;

/// <summary>
/// Detects sensitive operations performed outside of business hours (08:00–18:00).
/// MITRE ATT&CK: T1078 – Valid Accounts (Persistence)
/// </summary>
public class AfterHoursActivityRule : IDetectionRule
{
    public string Name => "After-Hours Sensitive Activity";
    public string MitreTechnique => "T1078";
    public string MitreTactic => "Persistence";
    public string Severity => "Medium";
    public bool IsEnabled { get; set; } = true;

    private readonly TimeSpan _businessStart = new(8, 0, 0);
    private readonly TimeSpan _businessEnd = new(18, 0, 0);

    private static readonly HashSet<string> SensitiveActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "LoginSuccess", "FileAccess", "USBDeviceConnected", "ProcessCreate"
    };

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        foreach (var ev in events.Where(e => SensitiveActions.Contains(e.EventAction)))
        {
            var localTime = ev.Timestamp.ToLocalTime().TimeOfDay;
            if (localTime < _businessStart || localTime > _businessEnd)
            {
                alerts.Add(new Alert
                {
                    Title = $"After-Hours Activity – {ev.AffectedUser}",
                    Description = $"Sensitive operation '{ev.EventAction}' by '{ev.AffectedUser}' at {ev.Timestamp:HH:mm} UTC " +
                                  $"on device '{ev.AffectedDevice}' (outside business hours).",
                    Severity = Core.Enums.Severity.Medium,
                    DetectionRuleName = Name,
                    MitreTechnique = MitreTechnique,
                    MitreTactic = MitreTactic,
                    AffectedUser = ev.AffectedUser,
                    AffectedDevice = ev.AffectedDevice,
                    SourceIP = ev.SourceIP,
                    EventId = ev.Id,
                    RecommendedAction = "Verify with user, check for unauthorized access patterns"
                });
            }
        }

        return Task.FromResult(alerts);
    }
}
