using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules;

/// <summary>
/// Detects files with hashes matching known threat intelligence indicators.
/// MITRE ATT&CK: T1204 – User Execution (Execution)
/// </summary>
public class SuspiciousHashRule : IDetectionRule
{
    public string Name => "Suspicious File Hash";
    public string MitreTechnique => "T1204";
    public string MitreTactic => "Execution";
    public string Severity => "Critical";
    public bool IsEnabled { get; set; } = true;

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var hashEvents = events
            .Where(e => e.IsThreatIntelMatch && !string.IsNullOrEmpty(e.FileHash))
            .ToList();

        foreach (var ev in hashEvents)
        {
            alerts.Add(new Alert
            {
                Title = $"Malicious File Hash Detected on {ev.AffectedDevice}",
                Description = $"File with hash '{ev.FileHash}' matches a known threat intelligence indicator. " +
                              $"User: {ev.AffectedUser}, Device: {ev.AffectedDevice}.",
                Severity = Core.Enums.Severity.Critical,
                DetectionRuleName = Name,
                MitreTechnique = MitreTechnique,
                MitreTactic = MitreTactic,
                AffectedUser = ev.AffectedUser,
                AffectedDevice = ev.AffectedDevice,
                EventId = ev.Id,
                RecommendedAction = "Isolate the endpoint, quarantine the file, scan for lateral movement"
            });
        }

        return Task.FromResult(alerts);
    }
}
