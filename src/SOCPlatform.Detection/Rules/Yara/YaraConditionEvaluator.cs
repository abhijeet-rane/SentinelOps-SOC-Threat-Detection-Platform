using System.Text.RegularExpressions;

namespace SOCPlatform.Detection.Rules.Yara;

/// <summary>
/// Evaluates a YARA-lite condition expression against string-match results.
/// Supports:
///   any of them
///   all of them
///   N of them                (N = integer)
///   any of ($prefix*)        / all of ($prefix*) / N of ($prefix*)
///   $ident                   (single identifier)
///   $a and $b  /  $a or $b   (simple boolean, no precedence tricks)
/// </summary>
internal static class YaraConditionEvaluator
{
    public static bool Evaluate(string condition, Dictionary<string, bool> hits)
    {
        var c = condition.Trim();

        // "N of them"  | "any of them"  | "all of them"
        var mThem = Regex.Match(c, @"^(?<q>any|all|\d+)\s+of\s+them$", RegexOptions.IgnoreCase);
        if (mThem.Success)
            return CountSatisfied(mThem.Groups["q"].Value, hits.Values);

        // "N of ($prefix*)"
        var mSubset = Regex.Match(c, @"^(?<q>any|all|\d+)\s+of\s+\(\$(?<prefix>[a-zA-Z0-9_]+)\*\)$", RegexOptions.IgnoreCase);
        if (mSubset.Success)
        {
            var prefix = "$" + mSubset.Groups["prefix"].Value;
            var subset = hits.Where(kv => kv.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).Select(kv => kv.Value);
            return CountSatisfied(mSubset.Groups["q"].Value, subset);
        }

        // Boolean expression over single identifiers
        var tokens = c.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        bool? current = null;
        string? op = null;
        foreach (var tok in tokens)
        {
            if (tok.Equals("and", StringComparison.OrdinalIgnoreCase)) { op = "and"; continue; }
            if (tok.Equals("or",  StringComparison.OrdinalIgnoreCase)) { op = "or";  continue; }

            if (!tok.StartsWith('$')) return false; // unsupported token
            if (!hits.TryGetValue(tok, out var val)) val = false;

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

    private static bool CountSatisfied(string quantifier, IEnumerable<bool> values)
    {
        var list = values.ToList();
        var hit = list.Count(v => v);
        return quantifier.ToLowerInvariant() switch
        {
            "any" => hit >= 1,
            "all" => list.Count > 0 && hit == list.Count,
            _ when int.TryParse(quantifier, out var n) => hit >= n,
            _ => false
        };
    }
}
