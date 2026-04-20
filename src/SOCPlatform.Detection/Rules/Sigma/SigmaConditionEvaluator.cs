using System.Text.Json;
using System.Text.RegularExpressions;
using SOCPlatform.Core.Entities;

namespace SOCPlatform.Detection.Rules.Sigma;

/// <summary>
/// Evaluates a <see cref="SigmaRule"/>'s <c>condition</c> expression against a
/// single SecurityEvent. See SigmaRule docs for the supported grammar.
/// </summary>
internal static class SigmaConditionEvaluator
{
    public static bool Evaluate(SigmaRule rule, SecurityEvent e)
    {
        // Fast-path: a condition like "selection" is just "all clauses in that selection must match"
        if (rule.Selections.TryGetValue(rule.Condition.Trim(), out var onlySel))
            return EvaluateSelection(onlySel, e);

        var tokens = rule.Condition.ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) return false;

        // "all of selection_*"  / "1 of selection_*" / "any of selection_*"
        if (tokens.Length == 3 && tokens[1] == "of")
        {
            return tokens[0] switch
            {
                "all" => AllOf(tokens[2], rule, e),
                "1" or "any" => AnyOf(tokens[2], rule, e),
                _ => false
            };
        }

        // "selA and selB" / "selA or selB" / "selA and not selB"
        return EvaluateBinary(tokens, rule, e);
    }

    private static bool AllOf(string pattern, SigmaRule rule, SecurityEvent e)
    {
        var regex = PatternToRegex(pattern);
        var matched = rule.Selections.Where(kv => regex.IsMatch(kv.Key)).ToList();
        return matched.Count > 0 && matched.All(kv => EvaluateSelection(kv.Value, e));
    }

    private static bool AnyOf(string pattern, SigmaRule rule, SecurityEvent e)
    {
        var regex = PatternToRegex(pattern);
        return rule.Selections.Any(kv => regex.IsMatch(kv.Key) && EvaluateSelection(kv.Value, e));
    }

    private static Regex PatternToRegex(string pattern) =>
        new("^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$", RegexOptions.IgnoreCase);

    private static bool EvaluateBinary(string[] tokens, SigmaRule rule, SecurityEvent e)
    {
        // Reduce left-to-right. Good enough for our bundled rules — no precedence tricks.
        bool? current = null;
        bool negateNext = false;
        string? op = null;

        foreach (var tok in tokens)
        {
            if (tok == "not") { negateNext = !negateNext; continue; }
            if (tok is "and" or "or") { op = tok; continue; }

            if (!rule.Selections.TryGetValue(tok, out var sel)) return false; // unknown selection
            var val = EvaluateSelection(sel, e);
            if (negateNext) { val = !val; negateNext = false; }

            current = current is null ? val : op switch
            {
                "and" => current.Value && val,
                "or"  => current.Value || val,
                _     => val
            };
            op = null;
        }

        return current ?? false;
    }

    // ── Per-selection evaluation ─────────────────────────────────────────────

    private static bool EvaluateSelection(List<SigmaField> fields, SecurityEvent e)
        => fields.All(f => EvaluateField(f, e));

    private static bool EvaluateField(SigmaField field, SecurityEvent e)
    {
        var actual = ResolveField(e, field.FieldName);
        if (actual is null) return false;
        var act = actual.ToLowerInvariant();

        return field.Values.Any(v => Compare(act, v.ToLowerInvariant(), field.Modifier));
    }

    private static bool Compare(string actual, string expected, string modifier) => modifier switch
    {
        "equals"     => actual == expected,
        "contains"   => actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
        "startswith" => actual.StartsWith(expected, StringComparison.OrdinalIgnoreCase),
        "endswith"   => actual.EndsWith(expected, StringComparison.OrdinalIgnoreCase),
        "re"         => Regex.IsMatch(actual, expected, RegexOptions.IgnoreCase),
        _            => actual == expected
    };

    /// <summary>
    /// Resolves a Sigma field name against a <see cref="SecurityEvent"/>. First checks
    /// the first-class strongly-typed columns, then falls back to the JSONB Metadata bag.
    /// </summary>
    private static string? ResolveField(SecurityEvent e, string fieldName) => fieldName switch
    {
        "EventCategory" or "Category" or "category"           => e.EventCategory,
        "EventAction"   or "Action"   or "action"             => e.EventAction,
        "Severity"      or "severity"                         => e.Severity,
        "MitreTechnique" or "mitre_technique"                 => e.MitreTechnique,
        "MitreTactic"    or "mitre_tactic"                    => e.MitreTactic,
        "AffectedUser"   or "User" or "user" or "TargetUser"  => e.AffectedUser,
        "AffectedDevice" or "Computer" or "computer"          => e.AffectedDevice,
        "SourceIP"       or "src_ip"                          => e.SourceIP,
        "DestinationIP"  or "dst_ip"                          => e.DestinationIP,
        "DestinationPort" or "dst_port"                       => e.DestinationPort?.ToString(),
        "FileHash"       or "hash"                            => e.FileHash,
        _ => ReadFromMetadata(e, fieldName)
    };

    private static string? ReadFromMetadata(SecurityEvent e, string key)
    {
        if (string.IsNullOrEmpty(e.Metadata)) return null;
        try
        {
            using var doc = JsonDocument.Parse(e.Metadata);
            return doc.RootElement.TryGetProperty(key, out var v)
                ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString()
                : null;
        }
        catch { return null; }
    }
}
