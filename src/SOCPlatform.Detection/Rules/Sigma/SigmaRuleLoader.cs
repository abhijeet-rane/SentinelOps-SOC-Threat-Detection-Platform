using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using YamlDotNet.RepresentationModel;

namespace SOCPlatform.Detection.Rules.Sigma;

/// <summary>
/// Loads Sigma rules from a directory of .yml files, parses the subset we
/// support, and returns a list of <see cref="SigmaRule"/>.
/// Failures on individual rules are logged but don't blow up the rest.
/// </summary>
public sealed class SigmaRuleLoader
{
    private readonly ILogger<SigmaRuleLoader> _logger;

    public SigmaRuleLoader(ILogger<SigmaRuleLoader> logger) => _logger = logger;

    public IReadOnlyList<SigmaRule> LoadFromDirectory(string directory)
    {
        if (!Directory.Exists(directory))
        {
            _logger.LogWarning("Sigma rule directory not found: {Dir}", directory);
            return Array.Empty<SigmaRule>();
        }

        var rules = new List<SigmaRule>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.yml", SearchOption.AllDirectories))
        {
            try
            {
                var parsed = ParseFile(file);
                if (parsed is not null) rules.Add(parsed);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse Sigma rule file {File}", file);
            }
        }

        _logger.LogInformation("Loaded {Count} Sigma rules from {Dir}", rules.Count, directory);
        return rules;
    }

    // ───────────────────────────────────────────────────────────────────────
    //  Parsing
    // ───────────────────────────────────────────────────────────────────────

    public static SigmaRule? ParseFile(string path)
    {
        using var reader = new StreamReader(path);
        var yaml = new YamlStream();
        yaml.Load(reader);
        if (yaml.Documents.Count == 0) return null;

        var root = (YamlMappingNode)yaml.Documents[0].RootNode;

        string? Get(string k) => root.Children.TryGetValue(new YamlScalarNode(k), out var n) && n is YamlScalarNode sn ? sn.Value : null;

        var title = Get("title") ?? Path.GetFileNameWithoutExtension(path);
        var id = Get("id") ?? $"sigma-{Path.GetFileNameWithoutExtension(path)}";
        var description = Get("description") ?? "";
        var level = Get("level") ?? "medium";

        // tags (optional) — may encode MITRE technique id
        var tags = new List<string>();
        string? mitreTechnique = null;
        string? mitreTactic = null;
        if (root.Children.TryGetValue(new YamlScalarNode("tags"), out var tagsNode) && tagsNode is YamlSequenceNode tagsSeq)
        {
            foreach (var t in tagsSeq.Children.OfType<YamlScalarNode>())
            {
                if (t.Value is null) continue;
                tags.Add(t.Value);
                var m = Regex.Match(t.Value, @"^attack\.t(\d{4}(?:\.\d{3})?)$", RegexOptions.IgnoreCase);
                if (m.Success) mitreTechnique = "T" + m.Groups[1].Value;
                if (t.Value.StartsWith("attack.", StringComparison.OrdinalIgnoreCase) && !t.Value.StartsWith("attack.t", StringComparison.OrdinalIgnoreCase))
                    mitreTactic = char.ToUpper(t.Value[7]) + t.Value[8..].Replace('_', ' ');
            }
        }

        // detection block
        if (!root.Children.TryGetValue(new YamlScalarNode("detection"), out var detectionNode) || detectionNode is not YamlMappingNode detection)
            return null;

        var condition = "selection";
        var selections = new Dictionary<string, List<SigmaField>>();

        foreach (var kvp in detection.Children)
        {
            var key = ((YamlScalarNode)kvp.Key).Value!;
            if (key == "condition")
            {
                if (kvp.Value is YamlScalarNode c) condition = c.Value ?? "selection";
                continue;
            }
            if (kvp.Value is not YamlMappingNode selectionMap) continue;

            var fields = new List<SigmaField>();
            foreach (var fieldKvp in selectionMap.Children)
            {
                var rawKey = ((YamlScalarNode)fieldKvp.Key).Value!;
                var (fieldName, modifier) = SplitFieldKey(rawKey);
                var values = NodeToStringList(fieldKvp.Value);
                if (values.Count > 0)
                    fields.Add(new SigmaField(fieldName, modifier, values));
            }
            selections[key] = fields;
        }

        return new SigmaRule
        {
            Id = id,
            Title = title,
            Description = description,
            Level = level.ToLowerInvariant(),
            Tags = tags,
            MitreTechnique = mitreTechnique,
            MitreTactic = mitreTactic,
            Condition = condition,
            Selections = selections
        };
    }

    public static (string field, string modifier) SplitFieldKey(string raw)
    {
        var pipe = raw.IndexOf('|');
        return pipe < 0 ? (raw, "equals") : (raw[..pipe], raw[(pipe + 1)..]);
    }

    private static List<string> NodeToStringList(YamlNode node) => node switch
    {
        YamlScalarNode s when s.Value is not null => new List<string> { s.Value },
        YamlSequenceNode seq => seq.Children.OfType<YamlScalarNode>().Select(c => c.Value ?? "").Where(v => v.Length > 0).ToList(),
        _ => new List<string>()
    };
}
