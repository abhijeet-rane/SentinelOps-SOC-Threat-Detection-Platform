using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules;

/// <summary>
/// Detects brute force login attempts: ≥5 failed logins from the same source in 5 minutes.
/// MITRE ATT&CK: T1110 – Brute Force (Credential Access)
/// </summary>
public class BruteForceRule : IDetectionRule
{
    public string Name => "Brute Force Detection";
    public string MitreTechnique => "T1110";
    public string MitreTactic => "Credential Access";
    public string Severity => "High";
    public bool IsEnabled { get; set; } = true;

    private readonly int _threshold;
    private readonly TimeSpan _window;

    public BruteForceRule(int threshold = 5, int windowSeconds = 300)
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

        // Group by source IP and check threshold within time window
        var groups = failedLogins.GroupBy(e => e.SourceIP);

        foreach (var group in groups)
        {
            var ordered = group.OrderBy(e => e.Timestamp).ToList();

            for (int i = _threshold - 1; i < ordered.Count; i++)
            {
                var windowStart = ordered[i].Timestamp - _window;
                var inWindow = ordered.Count(e => e.Timestamp >= windowStart && e.Timestamp <= ordered[i].Timestamp);

                if (inWindow >= _threshold)
                {
                    alerts.Add(new Alert
                    {
                        Title = $"Brute Force Detected from {group.Key}",
                        Description = $"{inWindow} failed login attempts from {group.Key} within {_window.TotalMinutes} minutes. " +
                                      $"Targeted users: {string.Join(", ", group.Select(e => e.AffectedUser).Distinct().Take(5))}",
                        Severity = Core.Enums.Severity.High,
                        DetectionRuleName = Name,
                        MitreTechnique = MitreTechnique,
                        MitreTactic = MitreTactic,
                        SourceIP = group.Key,
                        AffectedUser = group.First().AffectedUser,
                        AffectedDevice = group.First().AffectedDevice,
                        EventId = ordered[i].Id,
                        RecommendedAction = "Block source IP, reset affected accounts, investigate for credential stuffing"
                    });
                    break; // One alert per source IP
                }
            }
        }

        return Task.FromResult(alerts);
    }
}
