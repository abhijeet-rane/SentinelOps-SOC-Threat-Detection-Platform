using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Detection.Rules.Yara;

/// <summary>
/// Adapter that matches every loaded <see cref="YaraRule"/> against the raw
/// payload of every event's underlying Log. Unlike the Sigma engine (which
/// matches against structured fields), YARA is a byte/string pattern matcher
/// over blobs — so we pull Log.RawData for each event and run the rule set
/// over that payload.
/// </summary>
public sealed class YaraDetectionRule : IDetectionRule
{
    public string Name => "YARA Rule Engine";
    public string MitreTechnique => "T1204";
    public string MitreTactic => "Execution";
    public string Severity => "High";
    public bool IsEnabled { get; set; } = true;

    public IReadOnlyList<YaraRule> LoadedRules { get; }

    private readonly IServiceProvider _services;
    private readonly ILogger<YaraDetectionRule> _logger;

    public YaraDetectionRule(
        YaraRuleLoader loader,
        IServiceProvider services,
        ILogger<YaraDetectionRule> logger)
    {
        _services = services;
        _logger = logger;
        var dir = Path.Combine(AppContext.BaseDirectory, "Rules", "Yara", "Definitions");
        LoadedRules = loader.LoadFromDirectory(dir);
    }

    public async Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();
        if (LoadedRules.Count == 0 || events.Count == 0) return alerts;

        // Collect Log.RawData for every event (batch query for performance).
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();

        var logIds = events.Select(e => e.LogId).Distinct().ToList();
        var rawByLogId = await db.Logs
            .Where(l => logIds.Contains(l.Id))
            .Select(l => new { l.Id, l.RawData })
            .ToDictionaryAsync(l => l.Id, l => l.RawData, ct);

        foreach (var ev in events)
        {
            if (!rawByLogId.TryGetValue(ev.LogId, out var raw) || string.IsNullOrEmpty(raw)) continue;

            foreach (var rule in LoadedRules)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (!rule.Matches(raw)) continue;

                    alerts.Add(new Alert
                    {
                        Title = $"[YARA] {rule.Name}",
                        Description = $"{rule.Description}\n\nMeta: {JsonSerializer.Serialize(rule.Meta)}",
                        Severity = MapSeverity(rule.Severity),
                        DetectionRuleName = $"YARA · {rule.Name}",
                        MitreTechnique = rule.Mitre ?? ev.MitreTechnique ?? MitreTechnique,
                        MitreTactic = ev.MitreTactic ?? MitreTactic,
                        SourceIP = ev.SourceIP,
                        AffectedDevice = ev.AffectedDevice,
                        AffectedUser = ev.AffectedUser,
                        EventId = ev.Id,
                        RecommendedAction = $"Investigate log payload matching YARA rule '{rule.Name}' — inspect attached binary / command"
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "YARA rule {Rule} evaluation error on event {EventId}", rule.Name, ev.Id);
                }
            }
        }
        return alerts;
    }

    private static Core.Enums.Severity MapSeverity(string s) => s.ToLowerInvariant() switch
    {
        "critical" => Core.Enums.Severity.Critical,
        "high"     => Core.Enums.Severity.High,
        "medium"   => Core.Enums.Severity.Medium,
        _          => Core.Enums.Severity.Low
    };
}
