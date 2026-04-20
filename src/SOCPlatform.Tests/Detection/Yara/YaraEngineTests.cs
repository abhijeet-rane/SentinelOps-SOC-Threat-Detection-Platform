using FluentAssertions;
using SOCPlatform.Detection.Rules.Yara;

namespace SOCPlatform.Tests.Detection.Yara;

public class YaraEngineTests
{
    [Fact]
    public void Parse_StringLiteral_Pattern()
    {
        var p = YaraRuleLoader.ParseStringPattern("$s1", "\"mimikatz\"");
        p.Type.Should().Be(YaraPatternType.String);
        p.Pattern.Should().Be("mimikatz");
        p.NoCase.Should().BeFalse();
    }

    [Fact]
    public void Parse_NoCase_Modifier()
    {
        var p = YaraRuleLoader.ParseStringPattern("$s2", "\"mimikatz\" nocase");
        p.NoCase.Should().BeTrue();
        p.Pattern.Should().Be("mimikatz");
    }

    [Fact]
    public void Parse_HexBytes_Pattern()
    {
        var p = YaraRuleLoader.ParseStringPattern("$h1", "{ 48 65 6c 6c 6f }");
        p.Type.Should().Be(YaraPatternType.HexBytes);
        p.Pattern.Trim().Should().Contain("48 65 6c 6c 6f");
    }

    [Fact]
    public void Parse_Regex_Pattern_With_Flags()
    {
        var p = YaraRuleLoader.ParseStringPattern("$r1", "/evil[0-9]+/i");
        p.Type.Should().Be(YaraPatternType.Regex);
        p.Pattern.Should().Be("evil[0-9]+");
        p.NoCase.Should().BeTrue();
    }

    [Fact]
    public void StringPattern_Matches_Case_Sensitive_Exact()
    {
        var rule = new YaraRule
        {
            Name = "R",
            Strings = { new YaraStringPattern("$s1", "badword", YaraPatternType.String, NoCase: false) },
            Condition = "any of them"
        };
        rule.Matches("hello badword here").Should().BeTrue();
        rule.Matches("hello BadWord here").Should().BeFalse();
    }

    [Fact]
    public void StringPattern_NoCase_Matches()
    {
        var rule = new YaraRule
        {
            Name = "R",
            Strings = { new YaraStringPattern("$s1", "badword", YaraPatternType.String, NoCase: true) },
            Condition = "any of them"
        };
        rule.Matches("hello BadWord here").Should().BeTrue();
    }

    [Fact]
    public void Regex_Pattern_Matches()
    {
        var rule = new YaraRule
        {
            Name = "R",
            Strings = { new YaraStringPattern("$r1", @"evil_[a-z]+\d+", YaraPatternType.Regex, NoCase: false) },
            Condition = "any of them"
        };
        rule.Matches("found evil_abc42 in payload").Should().BeTrue();
        rule.Matches("nothing bad").Should().BeFalse();
    }

    [Fact]
    public void Condition_All_Of_Them_Requires_Every_String()
    {
        var rule = new YaraRule
        {
            Name = "R",
            Strings =
            {
                new YaraStringPattern("$a", "alpha", YaraPatternType.String, false),
                new YaraStringPattern("$b", "beta", YaraPatternType.String, false),
            },
            Condition = "all of them"
        };
        rule.Matches("alpha").Should().BeFalse();
        rule.Matches("alpha beta").Should().BeTrue();
    }

    [Fact]
    public void Condition_N_Of_Them()
    {
        var rule = new YaraRule
        {
            Name = "R",
            Strings =
            {
                new YaraStringPattern("$a", "alpha", YaraPatternType.String, false),
                new YaraStringPattern("$b", "beta", YaraPatternType.String, false),
                new YaraStringPattern("$c", "gamma", YaraPatternType.String, false),
            },
            Condition = "2 of them"
        };
        rule.Matches("alpha only").Should().BeFalse();
        rule.Matches("alpha beta").Should().BeTrue();
        rule.Matches("alpha beta gamma").Should().BeTrue();
    }

    [Fact]
    public void Condition_Any_Of_Subset_With_Prefix()
    {
        var rule = new YaraRule
        {
            Name = "R",
            Strings =
            {
                new YaraStringPattern("$s1", "foo", YaraPatternType.String, false),
                new YaraStringPattern("$s2", "bar", YaraPatternType.String, false),
                new YaraStringPattern("$other", "baz", YaraPatternType.String, false),
            },
            Condition = "any of ($s*)"
        };

        rule.Matches("baz only").Should().BeFalse();
        rule.Matches("foo here").Should().BeTrue();
    }

    [Fact]
    public void LoadRule_Parses_Full_Yar_File()
    {
        var yar = """
        rule Test_Rule {
          meta:
            description = "Sample"
            severity = "high"
            mitre = "T1059"
          strings:
            $a = "findme" nocase
            $b = "alsofindme"
          condition:
            any of them
        }
        """;
        var tmp = Path.GetTempFileName() + ".yar";
        File.WriteAllText(tmp, yar);
        try
        {
            var dir = Path.GetDirectoryName(tmp)!;
            var renamed = Path.Combine(dir, $"test-{Guid.NewGuid():N}.yar");
            File.Move(tmp, renamed);
            try
            {
                var loader = new YaraRuleLoader(Microsoft.Extensions.Logging.Abstractions.NullLogger<YaraRuleLoader>.Instance);
                var rules = loader.LoadFromDirectory(dir);
                var test = rules.FirstOrDefault(r => r.Name == "Test_Rule");
                test.Should().NotBeNull();
                test!.Meta["severity"].Should().Be("high");
                test.Mitre.Should().Be("T1059");
                test.Matches("findME here").Should().BeTrue();
            }
            finally { if (File.Exists(renamed)) File.Delete(renamed); }
        }
        finally { if (File.Exists(tmp)) File.Delete(tmp); }
    }
}
