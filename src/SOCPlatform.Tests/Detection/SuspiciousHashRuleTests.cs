using FluentAssertions;
using SOCPlatform.Detection.Rules;

namespace SOCPlatform.Tests.Detection;

/// <summary>
/// Unit tests for SuspiciousHashRule.
/// Rule: IsThreatIntelMatch=true AND FileHash present → Critical alert.
/// </summary>
public class SuspiciousHashRuleTests
{
    private readonly SuspiciousHashRule _rule = new();

    [Fact]
    public async Task Returns_Alert_For_ThreatIntelMatch_With_Hash()
    {
        var ev = TestHelpers.MaliciousHashEvent(isThreatMatch: true, hash: "aabbccdd1122");
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().HaveCount(1);
        alerts[0].Severity.Should().Be(Core.Enums.Severity.Critical);
        alerts[0].MitreTechnique.Should().Be("T1204");
        alerts[0].MitreTactic.Should().Be("Execution");
        alerts[0].Title.Should().Contain("Malicious File Hash");
    }

    [Fact]
    public async Task No_Alert_When_ThreatIntelMatch_Is_False()
    {
        var ev = TestHelpers.MaliciousHashEvent(isThreatMatch: false, hash: "aabbccdd1122");
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task No_Alert_When_Hash_Is_Null()
    {
        var ev = TestHelpers.MaliciousHashEvent(isThreatMatch: true);
        ev.FileHash = null; // override
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task No_Alert_When_Hash_Is_Empty_String()
    {
        var ev = TestHelpers.MaliciousHashEvent(isThreatMatch: true);
        ev.FileHash = string.Empty;
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Multiple_Matches_Produce_Multiple_Alerts()
    {
        var events = new[]
        {
            TestHelpers.MaliciousHashEvent(true, "hash1", "user1"),
            TestHelpers.MaliciousHashEvent(true, "hash2", "user2"),
        };

        var alerts = await _rule.EvaluateAsync(events.ToList());

        alerts.Should().HaveCount(2);
    }

    [Fact]
    public async Task Alert_Description_Contains_Hash_And_User()
    {
        var ev = TestHelpers.MaliciousHashEvent(true, "deadbeef12345678", "victimUser");
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts[0].Description.Should().Contain("deadbeef12345678");
        alerts[0].Description.Should().Contain("victimUser");
        alerts[0].RecommendedAction.Should().Contain("quarantine");
    }

    [Fact]
    public async Task Empty_Events_Returns_No_Alerts()
    {
        var alerts = await _rule.EvaluateAsync([]);
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Mix_Of_Match_And_NoMatch_Only_Flags_Matches()
    {
        var events = new[]
        {
            TestHelpers.MaliciousHashEvent(true, "badHash"),
            TestHelpers.MaliciousHashEvent(false, "goodHash"),
            TestHelpers.MaliciousHashEvent(true, "anotherBadHash"),
        };

        var alerts = await _rule.EvaluateAsync(events.ToList());

        alerts.Should().HaveCount(2);
        alerts.All(a => a.Severity == Core.Enums.Severity.Critical).Should().BeTrue();
    }
}
