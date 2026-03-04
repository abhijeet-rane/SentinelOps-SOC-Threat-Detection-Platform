using FluentAssertions;
using SOCPlatform.Detection.Rules;

namespace SOCPlatform.Tests.Detection;

/// <summary>
/// Unit tests for PolicyViolationRule.
/// Rule: FileAccess in the "Security" event category → Medium alert.
/// </summary>
public class PolicyViolationRuleTests
{
    private readonly PolicyViolationRule _rule = new();

    [Fact]
    public async Task Returns_Alert_For_FileAccess_In_Security_Category()
    {
        var ev = TestHelpers.FileAccess(user: "intern", category: "Security");
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().HaveCount(1);
        alerts[0].Severity.Should().Be(Core.Enums.Severity.Medium);
        alerts[0].MitreTechnique.Should().Be("T1078");
        alerts[0].Title.Should().Contain("Policy Violation");
        alerts[0].AffectedUser.Should().Be("intern");
    }

    [Fact]
    public async Task No_Alert_For_FileAccess_In_Non_Security_Category()
    {
        var ev = TestHelpers.FileAccess(user: "intern", category: "Application");
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task No_Alert_For_LoginSuccess_In_Security_Category()
    {
        // Wrong EventAction — rule only looks for FileAccess
        var ev = TestHelpers.LoginSuccess(user: "alice");
        ev.EventCategory = "Security";
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Multiple_Violations_Produce_Multiple_Alerts()
    {
        var events = Enumerable.Range(1, 5)
            .Select(i => TestHelpers.FileAccess($"user{i}", "Security"))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().HaveCount(5);
    }

    [Fact]
    public async Task Alert_Description_Contains_User_And_Device()
    {
        var ev = TestHelpers.FileAccess("sensitiveUser", "Security");
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts[0].Description.Should().Contain("sensitiveUser");
        alerts[0].RecommendedAction.Should().Contain("access");
    }

    [Fact]
    public async Task Alert_Contains_SourceIP()
    {
        var ev = TestHelpers.FileAccess(sourceIp: "10.5.5.5", category: "Security");
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts[0].SourceIP.Should().Be("10.5.5.5");
    }

    [Fact]
    public async Task Empty_Events_Returns_No_Alerts()
    {
        var alerts = await _rule.EvaluateAsync([]);
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Mixed_Categories_Only_Flags_Security_Category()
    {
        var events = new[]
        {
            TestHelpers.FileAccess("u1", "Security"),
            TestHelpers.FileAccess("u2", "Application"),
            TestHelpers.FileAccess("u3", "Security"),
            TestHelpers.FileAccess("u4", "Network"),
        };

        var alerts = await _rule.EvaluateAsync(events.ToList());

        alerts.Should().HaveCount(2);
        alerts.All(a => a.AffectedUser is "u1" or "u3").Should().BeTrue();
    }
}
