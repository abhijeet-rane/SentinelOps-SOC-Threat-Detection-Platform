using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules;

/// <summary>
/// Detects account enumeration: ≥10 failed logins targeting different accounts from the same source.
/// MITRE ATT&CK: T1087 – Account Discovery (Discovery)
/// </summary>
public class AccountEnumerationRule : IDetectionRule
{
    public string Name => "Account Enumeration Detection";
    public string MitreTechnique => "T1087";
    public string MitreTactic => "Discovery";
    public string Severity => "High";
    public bool IsEnabled { get; set; } = true;

    private readonly int _threshold;
    private readonly TimeSpan _window;

    public AccountEnumerationRule(int threshold = 10, int windowSeconds = 300)
    {
        _threshold = threshold;
        _window = TimeSpan.FromSeconds(windowSeconds);
    }

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var failedLogins = events
            .Where(e => e.EventAction == "LoginFailure" && !string.IsNullOrEmpty(e.SourceIP))
            .OrderBy(e => e.Timestamp)
            .ToList();

        // Group by source IP and count distinct targeted usernames
        var groups = failedLogins.GroupBy(e => e.SourceIP);

        foreach (var group in groups)
        {
            var ordered = group.OrderBy(e => e.Timestamp).ToList();
            var latest = ordered.Last();
            var windowStart = latest.Timestamp - _window;

            var inWindow = ordered.Where(e => e.Timestamp >= windowStart).ToList();
            var distinctUsers = inWindow.Select(e => e.AffectedUser).Distinct().ToList();

            if (distinctUsers.Count >= _threshold)
            {
                alerts.Add(new Alert
                {
                    Title = $"Account Enumeration from {group.Key}",
                    Description = $"Source {group.Key} attempted login to {distinctUsers.Count} different accounts " +
                                  $"within {_window.TotalMinutes} minutes: {string.Join(", ", distinctUsers.Take(10))}",
                    Severity = Core.Enums.Severity.High,
                    DetectionRuleName = Name,
                    MitreTechnique = MitreTechnique,
                    MitreTactic = MitreTactic,
                    SourceIP = group.Key,
                    AffectedDevice = latest.AffectedDevice,
                    EventId = latest.Id,
                    RecommendedAction = "Block source IP, enable CAPTCHA, check for credential stuffing tools"
                });
            }
        }

        return Task.FromResult(alerts);
    }
}
