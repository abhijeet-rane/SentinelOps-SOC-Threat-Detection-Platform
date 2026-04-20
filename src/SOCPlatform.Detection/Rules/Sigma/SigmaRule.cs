using SOCPlatform.Core.Entities;

namespace SOCPlatform.Detection.Rules.Sigma;

/// <summary>
/// Parsed representation of a single Sigma rule. Built by <see cref="SigmaRuleLoader"/>
/// from YAML and consumed by <see cref="SigmaDetectionRule"/>.
///
/// We implement a carefully bounded subset of the Sigma spec that covers the vast
/// majority of public rules without pulling in a full parser:
///   • detection.{selection_name}.{field} = value (equals match)
///   • detection.{selection_name}.{field}|contains = value
///   • detection.{selection_name}.{field}|startswith = value
///   • detection.{selection_name}.{field}|endswith = value
///   • detection.{selection_name}.{field}|re = regex
///   • list-valued match (OR across values)
///   • condition: selection_name  — match single selection
///   • condition: sel1 and sel2   — match both
///   • condition: sel1 or sel2    — match either
///   • condition: all of selection_*  — match every selection matching the prefix
///   • condition: 1 of selection_*    — match any one
/// Unknown condition syntax → rule skipped with a log warning.
/// </summary>
public sealed class SigmaRule
{
    public string Id { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Level { get; init; } = "medium";   // informational|low|medium|high|critical
    public string? MitreTechnique { get; init; }
    public string? MitreTactic { get; init; }
    public List<string> Tags { get; init; } = new();

    /// <summary>Raw condition expression (e.g. "selection" or "selection and not filter").</summary>
    public string Condition { get; init; } = "selection";

    /// <summary>Every named selection block under <c>detection:</c>.</summary>
    public Dictionary<string, List<SigmaField>> Selections { get; init; } = new();

    /// <summary>Evaluate this rule against a single SecurityEvent — returns true if the event matches.</summary>
    public bool Matches(SecurityEvent e) => SigmaConditionEvaluator.Evaluate(this, e);
}

/// <summary>
/// One field-match clause inside a selection. "user|contains: admin" parses to
/// <c>new SigmaField("user", "contains", ["admin"])</c>.
/// </summary>
public sealed record SigmaField(string FieldName, string Modifier, List<string> Values);
