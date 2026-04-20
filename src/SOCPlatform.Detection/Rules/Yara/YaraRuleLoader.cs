using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace SOCPlatform.Detection.Rules.Yara;

/// <summary>
/// Parses simplified .yar files and returns <see cref="YaraRule"/> objects.
/// Only the subset described on <see cref="YaraRule"/> is supported —
/// strings with <c>nocase</c>, hex patterns <c>{ .. }</c>, regex <c>/.../[i]</c>,
/// and the condition forms enumerated in <see cref="YaraConditionEvaluator"/>.
/// </summary>
public sealed class YaraRuleLoader
{
    private static readonly Regex RuleBlock = new(@"rule\s+(?<name>\w+)\s*\{(?<body>[^}]*(?:\{[^}]*\}[^}]*)*)\}", RegexOptions.Singleline);
    private static readonly Regex MetaLine = new(@"^\s*(?<k>\w+)\s*=\s*""(?<v>[^""]*)""\s*$", RegexOptions.Multiline);
    private static readonly Regex StringLine = new(@"^\s*(?<id>\$\w+)\s*=\s*(?<val>.+?)\s*$", RegexOptions.Multiline);

    private readonly ILogger<YaraRuleLoader> _logger;

    public YaraRuleLoader(ILogger<YaraRuleLoader> logger) => _logger = logger;

    public IReadOnlyList<YaraRule> LoadFromDirectory(string directory)
    {
        if (!Directory.Exists(directory))
        {
            _logger.LogWarning("YARA rule directory not found: {Dir}", directory);
            return Array.Empty<YaraRule>();
        }

        var rules = new List<YaraRule>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.yar", SearchOption.AllDirectories))
        {
            try
            {
                var text = File.ReadAllText(file);
                foreach (Match m in RuleBlock.Matches(text))
                {
                    var name = m.Groups["name"].Value;
                    var body = m.Groups["body"].Value;
                    rules.Add(Parse(name, body));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse YARA file {File}", file);
            }
        }
        _logger.LogInformation("Loaded {Count} YARA rules from {Dir}", rules.Count, directory);
        return rules;
    }

    public static YaraRule Parse(string name, string body)
    {
        var meta = new Dictionary<string, string>();
        var strings = new List<YaraStringPattern>();
        string condition = "any of them";

        var sections = body.Split(new[] { "meta:", "strings:", "condition:" }, StringSplitOptions.None);
        // sections[0] is text before 'meta:', which we ignore.
        if (body.Contains("meta:"))
        {
            var metaBlock = ExtractBlock(body, "meta:");
            foreach (Match m in MetaLine.Matches(metaBlock)) meta[m.Groups["k"].Value] = m.Groups["v"].Value;
        }
        if (body.Contains("strings:"))
        {
            var stringBlock = ExtractBlock(body, "strings:");
            foreach (Match m in StringLine.Matches(stringBlock))
            {
                var id = m.Groups["id"].Value;
                var val = m.Groups["val"].Value.Trim();
                strings.Add(ParseStringPattern(id, val));
            }
        }
        if (body.Contains("condition:"))
        {
            condition = ExtractBlock(body, "condition:").Trim().TrimEnd(';').Trim();
            // single-line condition only — take the first non-empty line
            var firstLine = condition.Split('\n').Select(s => s.Trim()).FirstOrDefault(s => s.Length > 0);
            if (firstLine is not null) condition = firstLine;
        }

        return new YaraRule { Name = name, Meta = meta, Strings = strings, Condition = condition };
    }

    private static string ExtractBlock(string body, string header)
    {
        var idx = body.IndexOf(header, StringComparison.Ordinal);
        if (idx < 0) return "";
        var start = idx + header.Length;
        // next section header ends the block
        var next = new[] { "meta:", "strings:", "condition:" }
            .Select(h => body.IndexOf(h, start, StringComparison.Ordinal))
            .Where(i => i >= 0)
            .DefaultIfEmpty(body.Length)
            .Min();
        return body[start..next];
    }

    public static YaraStringPattern ParseStringPattern(string id, string val)
    {
        // hex:  { 48 65 6c 6c 6f }
        if (val.StartsWith('{') && val.EndsWith('}'))
        {
            var bytes = val.Trim('{', '}').Trim();
            return new YaraStringPattern(id, bytes, YaraPatternType.HexBytes, false);
        }
        // regex: /.../[i]
        if (val.StartsWith('/'))
        {
            var lastSlash = val.LastIndexOf('/');
            var pattern = val.Substring(1, lastSlash - 1);
            var flags = val[(lastSlash + 1)..].Trim();
            return new YaraStringPattern(id, pattern, YaraPatternType.Regex, flags.Contains('i'));
        }
        // string literal, optional nocase modifier
        var noCase = val.EndsWith(" nocase", StringComparison.OrdinalIgnoreCase);
        var quoted = noCase ? val[..^" nocase".Length].Trim() : val;
        var content = quoted.Trim('"');
        return new YaraStringPattern(id, content, YaraPatternType.String, noCase);
    }
}
