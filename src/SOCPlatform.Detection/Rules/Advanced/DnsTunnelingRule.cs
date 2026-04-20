using SOCPlatform.Core.Entities;

namespace SOCPlatform.Detection.Rules.Advanced;

/// <summary>
/// DNS tunneling / DNS data exfiltration. Attackers encode data in subdomain
/// labels and either query recursively to a controlled authoritative server or
/// push data via TXT/NULL records. We flag any of:
///   • subdomain length &gt; 50 chars (legit subdomains are rarely that long)
///   • Shannon entropy &gt; 4.0 bits/char on the subdomain (encoded base32/64)
///   • volume &gt; 100 queries/min to the same parent domain
///
/// MITRE ATT&amp;CK: T1572 – Protocol Tunneling
/// </summary>
public sealed class DnsTunnelingRule : IDetectionRule
{
    public string Name => "DNS Tunneling";
    public string MitreTechnique => "T1572";
    public string MitreTactic => "Command and Control";
    public string Severity => "High";
    public bool IsEnabled { get; set; } = true;

    private readonly int _maxSubdomainLength;
    private readonly double _maxEntropy;
    private readonly int _volumePerMinuteThreshold;

    public DnsTunnelingRule(int maxSubdomainLength = 50, double maxEntropy = 4.0, int volumePerMinuteThreshold = 100)
    {
        _maxSubdomainLength = maxSubdomainLength;
        _maxEntropy = maxEntropy;
        _volumePerMinuteThreshold = volumePerMinuteThreshold;
    }

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var dnsEvents = events
            .Where(e => e.EventAction is "DnsQuery" or "DnsResolution")
            .Select(e => new { Event = e, Domain = EventFieldExtractor.GetString(e, "domain") ?? EventFieldExtractor.GetString(e, "query_name") })
            .Where(x => !string.IsNullOrEmpty(x.Domain))
            .ToList();

        // Per-event checks: length + entropy
        foreach (var x in dnsEvents)
        {
            var (subdomain, parent) = SplitDomain(x.Domain!);

            var tooLong = subdomain.Length > _maxSubdomainLength;
            var entropy = EventFieldExtractor.ShannonEntropy(subdomain);
            var highEntropy = entropy > _maxEntropy && subdomain.Length >= 16; // avoid false-positives on short labels

            if (!tooLong && !highEntropy) continue;

            var reasons = new List<string>();
            if (tooLong) reasons.Add($"subdomain length {subdomain.Length} > {_maxSubdomainLength}");
            if (highEntropy) reasons.Add($"subdomain entropy {entropy:F2} bits/char > {_maxEntropy}");

            alerts.Add(new Alert
            {
                Title = $"DNS tunneling suspected: *.{parent}",
                Description = $"Query '{x.Domain}' tripped: {string.Join("; ", reasons)}. " +
                              "Long or high-entropy subdomains are a classic DNS-tunnel covert channel.",
                Severity = Core.Enums.Severity.High,
                DetectionRuleName = Name,
                MitreTechnique = MitreTechnique,
                MitreTactic = MitreTactic,
                SourceIP = x.Event.SourceIP,
                AffectedDevice = x.Event.AffectedDevice,
                AffectedUser = x.Event.AffectedUser,
                EventId = x.Event.Id,
                RecommendedAction = "Block the parent domain at DNS, inspect the querying process, isolate the host"
            });
        }

        // Volume check: >100 queries/min to same parent
        var volumeGroups = dnsEvents
            .GroupBy(x => SplitDomain(x.Domain!).parent)
            .Where(g => g.Count() >= _volumePerMinuteThreshold);

        foreach (var group in volumeGroups)
        {
            var sorted = group.OrderBy(x => x.Event.Timestamp).ToList();
            // Require the volume to fit inside a 1-min bucket somewhere
            for (int i = 0; i + _volumePerMinuteThreshold - 1 < sorted.Count; i++)
            {
                var span = sorted[i + _volumePerMinuteThreshold - 1].Event.Timestamp - sorted[i].Event.Timestamp;
                if (span.TotalMinutes > 1) continue;

                alerts.Add(new Alert
                {
                    Title = $"DNS tunneling suspected (volume): *.{group.Key}",
                    Description = $"{_volumePerMinuteThreshold}+ DNS queries to *.{group.Key} within one minute — characteristic of tunneled C2.",
                    Severity = Core.Enums.Severity.High,
                    DetectionRuleName = Name,
                    MitreTechnique = MitreTechnique,
                    MitreTactic = MitreTactic,
                    SourceIP = sorted[i].Event.SourceIP,
                    AffectedDevice = sorted[i].Event.AffectedDevice,
                    AffectedUser = sorted[i].Event.AffectedUser,
                    EventId = sorted[i].Event.Id,
                    RecommendedAction = $"Block *.{group.Key}, pcap the affected host, inspect DNS client process"
                });
                break; // one volume alert per parent domain
            }
        }

        return Task.FromResult(alerts);
    }

    public static (string subdomain, string parent) SplitDomain(string domain)
    {
        var clean = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var labels = clean.Split('.');
        if (labels.Length <= 2) return ("", clean);
        var parent = string.Join('.', labels[^2..]);
        var subdomain = string.Join('.', labels[..^2]);
        return (subdomain, parent);
    }
}
