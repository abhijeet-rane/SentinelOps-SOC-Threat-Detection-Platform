using System.Text.RegularExpressions;

namespace SOCPlatform.Detection.Rules.Yara;

/// <summary>
/// Lightweight in-process YARA-style rule. We support the subset of YARA
/// syntax that covers the vast majority of community rules without pulling
/// in libyara as a native dependency:
///
///   rule RuleName {
///     meta:
///       description = "..."
///       severity = "high"
///       mitre = "T1027"
///     strings:
///       $s1 = "plain string"
///       $s2 = "case insensitive" nocase
///       $h1 = { 48 65 6c 6c 6f }          // hex pattern
///       $r1 = /^malware_[a-z]+/i          // regex
///     condition:
///       any of them | all of them | 2 of them | any of ($s*)
///   }
///
/// Parsed once at startup, then evaluated cheaply per event payload.
/// </summary>
public sealed class YaraRule
{
    public string Name { get; init; } = string.Empty;
    public Dictionary<string, string> Meta { get; init; } = new();
    public List<YaraStringPattern> Strings { get; init; } = new();
    public string Condition { get; init; } = "any of them";

    public string Severity => Meta.TryGetValue("severity", out var s) ? s : "medium";
    public string? Mitre   => Meta.TryGetValue("mitre",    out var m) ? m : null;
    public string Description => Meta.TryGetValue("description", out var d) ? d : Name;

    /// <summary>Evaluate against a payload (e.g., Log.RawData). Returns true if the condition is satisfied.</summary>
    public bool Matches(string payload)
    {
        if (string.IsNullOrEmpty(payload)) return false;

        var hits = new Dictionary<string, bool>(Strings.Count);
        foreach (var s in Strings)
            hits[s.Identifier] = s.Matches(payload);

        return YaraConditionEvaluator.Evaluate(Condition, hits);
    }
}

public sealed record YaraStringPattern(string Identifier, string Pattern, YaraPatternType Type, bool NoCase)
{
    public bool Matches(string haystack) => Type switch
    {
        YaraPatternType.String => NoCase
            ? haystack.Contains(Pattern, StringComparison.OrdinalIgnoreCase)
            : haystack.Contains(Pattern, StringComparison.Ordinal),

        YaraPatternType.HexBytes => MatchHex(haystack),

        YaraPatternType.Regex => Regex.IsMatch(
            haystack, Pattern,
            NoCase ? RegexOptions.IgnoreCase : RegexOptions.None),

        _ => false
    };

    private bool MatchHex(string haystack)
    {
        // Pattern is stored as "48 65 6c 6c 6f" — find as a byte subsequence in the payload (UTF-8).
        try
        {
            var bytes = Pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(b => Convert.ToByte(b, 16)).ToArray();
            var asString = System.Text.Encoding.Latin1.GetString(bytes);
            return haystack.Contains(asString, StringComparison.Ordinal);
        }
        catch { return false; }
    }
}

public enum YaraPatternType { String, HexBytes, Regex }
