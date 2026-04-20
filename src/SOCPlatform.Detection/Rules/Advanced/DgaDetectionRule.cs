using SOCPlatform.Core.Entities;

namespace SOCPlatform.Detection.Rules.Advanced;

/// <summary>
/// Domain Generation Algorithm detector. DGA malware (Conficker, Necurs, Emotet, …)
/// generates thousands of random-looking domain names so take-downs can't keep up.
/// We score each queried domain against a bigram-frequency table trained on common
/// English: legit domains score high, random strings score low.
///
/// MITRE ATT&amp;CK: T1568.002 – Dynamic Resolution: Domain Generation Algorithms
/// </summary>
public sealed class DgaDetectionRule : IDetectionRule
{
    public string Name => "DGA Domain Detection";
    public string MitreTechnique => "T1568.002";
    public string MitreTactic => "Command and Control";
    public string Severity => "High";
    public bool IsEnabled { get; set; } = true;

    // Lower score = more random. Gibberish scores well below -5; real names score closer to -2.5.
    private readonly double _threshold;
    private readonly int _minLength;

    public DgaDetectionRule(double threshold = -6.3, int minLength = 8)
    {
        _threshold = threshold;
        _minLength = minLength;
    }

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var dnsEvents = events
            .Where(e => e.EventAction is "DnsQuery" or "DnsResolution")
            .ToList();

        foreach (var ev in dnsEvents)
        {
            var domain = EventFieldExtractor.GetString(ev, "domain")
                      ?? EventFieldExtractor.GetString(ev, "query_name");
            if (string.IsNullOrEmpty(domain)) continue;

            var secondLevel = ExtractSecondLevelLabel(domain);
            if (secondLevel.Length < _minLength) continue;

            var score = BigramScore(secondLevel);
            if (score > _threshold) continue;

            var entropy = EventFieldExtractor.ShannonEntropy(secondLevel);

            alerts.Add(new Alert
            {
                Title = $"Likely DGA domain queried: {domain}",
                Description = $"Domain '{secondLevel}' scored {score:F2} on bigram frequency check " +
                              $"(threshold {_threshold}, entropy {entropy:F2} bits/char). " +
                              "Low natural-language likelihood suggests an algorithmically generated name.",
                Severity = Core.Enums.Severity.High,
                DetectionRuleName = Name,
                MitreTechnique = MitreTechnique,
                MitreTactic = MitreTactic,
                SourceIP = ev.SourceIP,
                AffectedDevice = ev.AffectedDevice,
                AffectedUser = ev.AffectedUser,
                EventId = ev.Id,
                RecommendedAction = "Block the domain, inspect the querying process, hunt for sibling DGA domains"
            });
        }

        return Task.FromResult(alerts);
    }

    /// <summary>Return the label right below the TLD (e.g. "kq1zmq" for "kq1zmq.top").</summary>
    public static string ExtractSecondLevelLabel(string domain)
    {
        var clean = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var labels = clean.Split('.');
        return labels.Length >= 2 ? labels[^2] : clean;
    }

    /// <summary>
    /// Average log-probability per bigram against <see cref="EnglishBigramFrequency"/>.
    /// Unknown bigrams get assigned a floor (see constant below) so scores stay bounded.
    /// </summary>
    public static double BigramScore(string label)
    {
        if (label.Length < 2) return 0;

        double totalLogP = 0;
        int count = 0;
        for (int i = 0; i < label.Length - 1; i++)
        {
            var bigram = label.Substring(i, 2);
            if (!bigram.All(char.IsLetter)) continue;

            var freq = EnglishBigramFrequency.LookupOrFloor(bigram);
            totalLogP += Math.Log(freq);
            count++;
        }
        return count == 0 ? 0 : totalLogP / count;
    }
}
