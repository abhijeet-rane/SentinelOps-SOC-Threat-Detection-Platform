using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules;

/// <summary>
/// Detects port scanning: ≥20 connection attempts to different ports from the same source in 1 minute.
/// MITRE ATT&CK: T1046 – Network Service Discovery (Discovery)
/// </summary>
public class PortScanRule : IDetectionRule
{
    public string Name => "Port Scan Detection";
    public string MitreTechnique => "T1046";
    public string MitreTactic => "Discovery";
    public string Severity => "Medium";
    public bool IsEnabled { get; set; } = true;

    private readonly int _portThreshold;
    private readonly TimeSpan _window;

    public PortScanRule(int portThreshold = 20, int windowSeconds = 60)
    {
        _portThreshold = portThreshold;
        _window = TimeSpan.FromSeconds(windowSeconds);
    }

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var connectionEvents = events
            .Where(e => e.EventAction == "ActiveConnections" && !string.IsNullOrEmpty(e.SourceIP) && e.DestinationPort.HasValue)
            .ToList();

        var grouped = connectionEvents.GroupBy(e => e.SourceIP);

        foreach (var group in grouped)
        {
            var ordered = group.OrderBy(e => e.Timestamp).ToList();
            var distinctPorts = new HashSet<int>();

            foreach (var ev in ordered)
            {
                // Sliding window: count distinct ports within the time window
                var windowStart = ev.Timestamp - _window;
                var inWindow = ordered
                    .Where(e => e.Timestamp >= windowStart && e.Timestamp <= ev.Timestamp && e.DestinationPort.HasValue)
                    .Select(e => e.DestinationPort!.Value)
                    .Distinct()
                    .ToList();

                if (inWindow.Count >= _portThreshold)
                {
                    alerts.Add(new Alert
                    {
                        Title = $"Port Scan Detected from {group.Key}",
                        Description = $"Source {group.Key} attempted connections to {inWindow.Count} distinct ports " +
                                      $"within {_window.TotalSeconds}s. Ports: {string.Join(", ", inWindow.Take(10))}...",
                        Severity = Core.Enums.Severity.Medium,
                        DetectionRuleName = Name,
                        MitreTechnique = MitreTechnique,
                        MitreTactic = MitreTactic,
                        SourceIP = group.Key,
                        AffectedDevice = ev.AffectedDevice,
                        EventId = ev.Id,
                        RecommendedAction = "Block source IP at firewall, investigate for reconnaissance activity"
                    });
                    break;
                }
            }
        }

        return Task.FromResult(alerts);
    }
}
