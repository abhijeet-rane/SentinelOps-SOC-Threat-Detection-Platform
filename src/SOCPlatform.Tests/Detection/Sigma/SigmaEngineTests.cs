using FluentAssertions;
using SOCPlatform.Core.Entities;
using SOCPlatform.Detection.Rules.Sigma;

namespace SOCPlatform.Tests.Detection.Sigma;

public class SigmaEngineTests
{
    private static SigmaRule ParseInline(string yaml)
    {
        var tmp = Path.GetTempFileName() + ".yml";
        File.WriteAllText(tmp, yaml);
        try   { return SigmaRuleLoader.ParseFile(tmp)!; }
        finally { File.Delete(tmp); }
    }

    private static SecurityEvent ProcEvent(string processName, string? commandLine = null, string? user = "alice") => new()
    {
        EventAction = "ProcessCreate",
        AffectedUser = user,
        AffectedDevice = "WRK-001",
        Metadata = commandLine is null
            ? $"{{\"ProcessName\":\"{processName}\"}}"
            : $"{{\"ProcessName\":\"{processName}\",\"CommandLine\":\"{commandLine.Replace("\"", "\\\"")}\"}}"
    };

    [Fact]
    public void SplitFieldKey_Parses_Modifiers()
    {
        SigmaRuleLoader.SplitFieldKey("ProcessName|contains").Should().Be(("ProcessName", "contains"));
        SigmaRuleLoader.SplitFieldKey("user").Should().Be(("user", "equals"));
    }

    [Fact]
    public void Equals_Match_Works()
    {
        var rule = ParseInline("""
            title: eq
            id: t1
            detection:
              selection:
                EventAction: ProcessCreate
              condition: selection
            """);

        rule.Matches(ProcEvent("anything.exe")).Should().BeTrue();

        var other = ProcEvent("x");
        other.EventAction = "LoginSuccess";
        rule.Matches(other).Should().BeFalse();
    }

    [Fact]
    public void Contains_Modifier_Is_Case_Insensitive_Any_Of_Values()
    {
        var rule = ParseInline("""
            title: c
            id: t2
            detection:
              selection:
                EventAction: ProcessCreate
                ProcessName|contains:
                  - psexec.exe
                  - mimikatz.exe
              condition: selection
            """);

        rule.Matches(ProcEvent("PsExec.exe")).Should().BeTrue();
        rule.Matches(ProcEvent("notepad.exe")).Should().BeFalse();
    }

    [Fact]
    public void EndsWith_Modifier()
    {
        var rule = ParseInline("""
            title: e
            id: t3
            detection:
              selection:
                EventAction: ProcessCreate
                ProcessName|endswith: .exe
              condition: selection
            """);

        rule.Matches(ProcEvent("foo.exe")).Should().BeTrue();
        rule.Matches(ProcEvent("foo.dll")).Should().BeFalse();
    }

    [Fact]
    public void AND_Condition_Requires_Both_Selections()
    {
        var rule = ParseInline("""
            title: and
            id: t4
            detection:
              selection:
                EventAction: ProcessCreate
                ProcessName|endswith: schtasks.exe
              filter:
                CommandLine|contains:
                  - /ru system
              condition: selection and filter
            """);

        rule.Matches(ProcEvent("schtasks.exe", "/create /ru SYSTEM /tn evil")).Should().BeTrue();
        rule.Matches(ProcEvent("schtasks.exe", "/query")).Should().BeFalse();
    }

    [Fact]
    public void Tags_Parsed_For_MITRE_Technique_Extraction()
    {
        var rule = ParseInline("""
            title: m
            id: t5
            tags:
              - attack.execution
              - attack.t1059.001
            detection:
              selection:
                EventAction: ProcessCreate
              condition: selection
            """);

        rule.MitreTechnique.Should().Be("T1059.001");
        rule.Tags.Should().Contain("attack.execution");
    }

    [Fact]
    public void Unknown_Field_Does_Not_Throw_Does_Not_Match()
    {
        var rule = ParseInline("""
            title: u
            id: t6
            detection:
              selection:
                NonExistentField: x
              condition: selection
            """);

        rule.Matches(ProcEvent("foo.exe")).Should().BeFalse();
    }
}
