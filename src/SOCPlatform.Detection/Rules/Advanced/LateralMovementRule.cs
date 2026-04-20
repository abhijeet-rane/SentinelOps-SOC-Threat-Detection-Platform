using SOCPlatform.Core.Entities;

namespace SOCPlatform.Detection.Rules.Advanced;

/// <summary>
/// Detects lateral movement: a single user successfully authenticating to
/// ≥ <see cref="_minDistinctHosts"/> distinct hosts inside a sliding
/// <see cref="_window"/> window. Legitimate users typically log in from one
/// workstation; hopping across 3+ servers in half an hour is a classic
/// post-breach kill-chain pattern (pass-the-hash, kerberoasting, etc.).
///
/// MITRE ATT&amp;CK: T1021 – Remote Services
/// </summary>
public sealed class LateralMovementRule : IDetectionRule
{
    public string Name => "Lateral Movement";
    public string MitreTechnique => "T1021";
    public string MitreTactic => "Lateral Movement";
    public string Severity => "High";
    public bool IsEnabled { get; set; } = true;

    private readonly int _minDistinctHosts;
    private readonly TimeSpan _window;

    public LateralMovementRule(int minDistinctHosts = 3, int windowMinutes = 30)
    {
        _minDistinctHosts = minDistinctHosts;
        _window = TimeSpan.FromMinutes(windowMinutes);
    }

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var successes = events
            .Where(e => e.EventAction is "LoginSuccess" or "AuthSuccess")
            .Where(e => !string.IsNullOrEmpty(e.AffectedUser))
            .Where(e => !string.IsNullOrEmpty(e.AffectedDevice))
            .OrderBy(e => e.Timestamp)
            .ToList();

        var byUser = successes.GroupBy(e => e.AffectedUser!);

        foreach (var user in byUser)
        {
            var ordered = user.OrderBy(e => e.Timestamp).ToList();

            // Slide the window forward and look for N distinct hosts within it
            for (int i = 0; i < ordered.Count; i++)
            {
                var windowEnd = ordered[i].Timestamp + _window;
                var hostsInWindow = ordered
                    .Where(e => e.Timestamp >= ordered[i].Timestamp && e.Timestamp <= windowEnd)
                    .Select(e => e.AffectedDevice!)
                    .Distinct()
                    .ToList();

                if (hostsInWindow.Count < _minDistinctHosts) continue;

                var first = ordered[i];
                alerts.Add(new Alert
                {
                    Title = $"Lateral movement by '{user.Key}' across {hostsInWindow.Count} hosts",
                    Description = $"User '{user.Key}' successfully authenticated to {hostsInWindow.Count} distinct hosts " +
                                  $"within {_window.TotalMinutes:F0} min: {string.Join(", ", hostsInWindow.Take(5))}" +
                                  (hostsInWindow.Count > 5 ? $" (+{hostsInWindow.Count - 5} more)" : ""),
                    Severity = Core.Enums.Severity.High,
                    DetectionRuleName = Name,
                    MitreTechnique = MitreTechnique,
                    MitreTactic = MitreTactic,
                    SourceIP = first.SourceIP,
                    AffectedDevice = first.AffectedDevice,
                    AffectedUser = user.Key,
                    EventId = first.Id,
                    RecommendedAction = $"Disable '{user.Key}' pending investigation, audit all sessions, hunt for pass-the-hash / kerberoasting artifacts"
                });
                break; // one alert per user per cycle
            }
        }

        return Task.FromResult(alerts);
    }
}
