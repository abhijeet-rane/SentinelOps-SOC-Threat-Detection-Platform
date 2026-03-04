using FluentAssertions;
using SOCPlatform.Detection.Rules;

namespace SOCPlatform.Tests.Detection;

/// <summary>
/// Unit tests for AccountEnumerationRule.
/// Rule: ≥10 distinct usernames targeted from same IP within 5 minutes → High alert.
/// </summary>
public class AccountEnumerationRuleTests
{
    private readonly AccountEnumerationRule _rule = new(threshold: 10, windowSeconds: 300);

    [Fact]
    public async Task Returns_Alert_When_10_Distinct_Users_From_Same_IP()
    {
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(1, 10)
            .Select(i => TestHelpers.LoginFailure("192.168.5.5", $"user{i}", timestamp: now.AddSeconds(-i * 10)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().HaveCount(1);
        alerts[0].SourceIP.Should().Be("192.168.5.5");
        alerts[0].Severity.Should().Be(Core.Enums.Severity.High);
        alerts[0].MitreTechnique.Should().Be("T1087");
        alerts[0].Title.Should().Contain("Account Enumeration");
    }

    [Fact]
    public async Task No_Alert_With_9_Distinct_Users()
    {
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(1, 9)
            .Select(i => TestHelpers.LoginFailure("192.168.5.6", $"user{i}", timestamp: now.AddSeconds(-i * 10)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Same_User_Multiple_Times_Counts_As_One_Distinct()
    {
        // 12 failures all targeting "jdoe" = only 1 distinct user → no enumeration alert
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(0, 12)
            .Select(i => TestHelpers.LoginFailure("192.168.5.7", "jdoe", timestamp: now.AddSeconds(-i * 5)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Each_Source_IP_Gets_Independent_Evaluation()
    {
        var now = DateTime.UtcNow;
        // IP A: 10 distinct users → alert
        var eventsA = Enumerable.Range(1, 10)
            .Select(i => TestHelpers.LoginFailure("10.10.10.1", $"alpha{i}", timestamp: now.AddSeconds(-i * 5)))
            .ToList();
        // IP B: only 5 distinct users → no alert
        var eventsB = Enumerable.Range(1, 5)
            .Select(i => TestHelpers.LoginFailure("10.10.10.2", $"beta{i}", timestamp: now.AddSeconds(-i * 5)))
            .ToList();

        var alerts = await _rule.EvaluateAsync([.. eventsA, .. eventsB]);

        alerts.Should().HaveCount(1);
        alerts[0].SourceIP.Should().Be("10.10.10.1");
    }

    [Fact]
    public async Task Alert_Description_Lists_Targeted_Users()
    {
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(1, 10)
            .Select(i => TestHelpers.LoginFailure("10.20.30.40", $"victim{i}", timestamp: now.AddSeconds(-i)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts[0].Description.Should().Contain("10.20.30.40");
        alerts[0].Description.Should().Contain("10"); // distinct account count
    }

    [Fact]
    public async Task Events_Outside_Window_Not_Counted()
    {
        var now = DateTime.UtcNow;
        // 10 distinct users but spread over 10 minutes — only 5 appear in any 5-min window
        var events = Enumerable.Range(1, 10)
            .Select(i => TestHelpers.LoginFailure("10.99.99.99", $"user{i}", timestamp: now.AddMinutes(-i)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Empty_Events_Returns_No_Alerts()
    {
        var alerts = await _rule.EvaluateAsync([]);
        alerts.Should().BeEmpty();
    }
}
