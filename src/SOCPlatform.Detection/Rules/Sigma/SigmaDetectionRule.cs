using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Detection.Rules.Sigma;

/// <summary>
/// Adapter that exposes all loaded <see cref="SigmaRule"/>s as a single
/// <see cref="IDetectionRule"/> to the DetectionEngine. Each Sigma match
/// produces its own Alert tagged with the Sigma rule's id/title.
/// </summary>
public sealed class SigmaDetectionRule : IDetectionRule
{
    public string Name => "Sigma Rule Engine";
    public string MitreTechnique => "Multiple";
    public string MitreTactic => "Multiple";
    public string Severity => "High";
    public bool IsEnabled { get; set; } = true;

    public IReadOnlyList<SigmaRule> LoadedRules { get; }

    private readonly ILogger<SigmaDetectionRule> _logger;

    public SigmaDetectionRule(SigmaRuleLoader loader, ILogger<SigmaDetectionRule> logger)
    {
        _logger = logger;
        var dir = Path.Combine(AppContext.BaseDirectory, "Rules", "Sigma", "Definitions");
        LoadedRules = loader.LoadFromDirectory(dir);
    }

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();
        if (LoadedRules.Count == 0) return Task.FromResult(alerts);

        foreach (var ev in events)
        {
            foreach (var rule in LoadedRules)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (!rule.Matches(ev)) continue;

                    alerts.Add(new Alert
                    {
                        Title = $"[Sigma] {rule.Title}",
                        Description = $"{rule.Description}\n\nRule: {rule.Id} · Level: {rule.Level} · Tags: {string.Join(", ", rule.Tags)}",
                        Severity = MapLevel(rule.Level),
                        DetectionRuleName = $"Sigma · {rule.Id}",
                        MitreTechnique = rule.MitreTechnique ?? ev.MitreTechnique,
                        MitreTactic = rule.MitreTactic ?? ev.MitreTactic,
                        SourceIP = ev.SourceIP,
                        AffectedDevice = ev.AffectedDevice,
                        AffectedUser = ev.AffectedUser,
                        EventId = ev.Id,
                        RecommendedAction = $"Investigate event matching Sigma rule {rule.Id}"
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Sigma rule {Id} evaluation error on event {EventId}", rule.Id, ev.Id);
                }
            }
        }
        return Task.FromResult(alerts);
    }

    private static Core.Enums.Severity MapLevel(string level) => level.ToLowerInvariant() switch
    {
        "critical" => Core.Enums.Severity.Critical,
        "high"     => Core.Enums.Severity.High,
        "medium"   => Core.Enums.Severity.Medium,
        _          => Core.Enums.Severity.Low
    };
}
