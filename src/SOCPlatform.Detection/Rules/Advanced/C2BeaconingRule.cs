using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules.Advanced;

/// <summary>
/// Detects command-and-control beaconing: a compromised host talks to a C2
/// server on a near-constant interval (low jitter). Real malware beaconing
/// often uses a fixed 60 s / 5 min / 1 h heartbeat; we flag any (src, dst)
/// pair that accumulates ≥ <see cref="_minConnections"/> connections within
/// the window where the inter-arrival jitter (std-dev / mean) is below
/// <see cref="_maxJitterRatio"/>.
///
/// MITRE ATT&amp;CK: T1071 – Application Layer Protocol (Command &amp; Control)
/// </summary>
public sealed class C2BeaconingRule : IDetectionRule
{
    public string Name => "C2 Beaconing";
    public string MitreTechnique => "T1071";
    public string MitreTactic => "Command and Control";
    public string Severity => "Critical";
    public bool IsEnabled { get; set; } = true;

    private readonly int _minConnections;
    private readonly double _maxJitterRatio;
    private readonly TimeSpan _window;

    public C2BeaconingRule(int minConnections = 10, double maxJitterRatio = 0.2, int windowMinutes = 60)
    {
        _minConnections = minConnections;
        _maxJitterRatio = maxJitterRatio;
        _window = TimeSpan.FromMinutes(windowMinutes);
    }

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var connections = events
            .Where(e => e.EventAction is "NetworkConnection" or "TcpConnect" or "OutboundConnection")
            .Where(e => !string.IsNullOrEmpty(e.DestinationIP))
            .OrderBy(e => e.Timestamp)
            .ToList();

        // Group by (source → destination) pair
        var pairs = connections.GroupBy(e => new { Src = e.SourceIP ?? e.AffectedDevice ?? "?", Dst = e.DestinationIP! });

        foreach (var pair in pairs)
        {
            var ordered = pair.OrderBy(e => e.Timestamp).ToList();
            if (ordered.Count < _minConnections) continue;

            // Only consider the subset within the sliding window
            var first = ordered.First().Timestamp;
            var inWindow = ordered.Where(e => e.Timestamp - first <= _window).ToList();
            if (inWindow.Count < _minConnections) continue;

            // Compute inter-arrival intervals
            var intervals = new double[inWindow.Count - 1];
            for (int i = 1; i < inWindow.Count; i++)
                intervals[i - 1] = (inWindow[i].Timestamp - inWindow[i - 1].Timestamp).TotalSeconds;

            if (intervals.Length == 0) continue;

            var mean = intervals.Average();
            if (mean <= 0) continue;

            var variance = intervals.Sum(x => (x - mean) * (x - mean)) / intervals.Length;
            var stdDev = Math.Sqrt(variance);
            var jitterRatio = stdDev / mean;

            if (jitterRatio >= _maxJitterRatio) continue; // too noisy, probably organic traffic

            alerts.Add(new Alert
            {
                Title = $"C2 beacon pattern: {pair.Key.Src} → {pair.Key.Dst}",
                Description = $"{inWindow.Count} connections over {(inWindow.Last().Timestamp - first).TotalMinutes:F1} min " +
                              $"with mean interval {mean:F1}s (jitter ratio {jitterRatio:F2}, threshold {_maxJitterRatio}). " +
                              "Periodic pattern suggests scripted beaconing to C2 infrastructure.",
                Severity = Core.Enums.Severity.Critical,
                DetectionRuleName = Name,
                MitreTechnique = MitreTechnique,
                MitreTactic = MitreTactic,
                SourceIP = pair.Key.Src,
                AffectedDevice = inWindow.First().AffectedDevice,
                AffectedUser = inWindow.First().AffectedUser,
                EventId = inWindow.First().Id,
                RecommendedAction = $"Isolate {pair.Key.Src}, investigate running processes, block {pair.Key.Dst} at perimeter"
            });
        }

        return Task.FromResult(alerts);
    }
}
