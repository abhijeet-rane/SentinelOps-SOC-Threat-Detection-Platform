using FluentAssertions;
using SOCPlatform.Detection.Rules;

namespace SOCPlatform.Tests.Detection;

/// <summary>
/// Unit tests for BruteForceRule.
/// Rule: ≥5 failed logins from the same source IP within 5 minutes triggers a High alert.
/// </summary>
public class BruteForceRuleTests
{
    private readonly BruteForceRule _rule = new(threshold: 5, windowSeconds: 300);

    [Fact]
    public async Task Returns_Alert_When_5_LoginFailures_SameIP_Within_Window()
    {
        // Arrange: 5 failures from the same IP, 1 minute apart (within 5-min window)
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(0, 5)
            .Select(i => TestHelpers.LoginFailure("10.0.0.1", $"user{i}", timestamp: now.AddMinutes(-4 + i)))
            .ToList();

        // Act
        var alerts = await _rule.EvaluateAsync(events);

        // Assert
        alerts.Should().HaveCount(1);
        alerts[0].SourceIP.Should().Be("10.0.0.1");
        alerts[0].Severity.Should().Be(Core.Enums.Severity.High);
        alerts[0].MitreTechnique.Should().Be("T1110");
        alerts[0].Title.Should().Contain("Brute Force");
    }

    [Fact]
    public async Task No_Alert_When_Fewer_Than_Threshold_Failures()
    {
        // Arrange: only 4 failures — one below threshold
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(0, 4)
            .Select(i => TestHelpers.LoginFailure("10.0.0.2", timestamp: now.AddMinutes(-i)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task No_Alert_When_Threshold_Met_But_Outside_Window()
    {
        // Arrange: 5 failures from same IP, but spread across 10 minutes (> 5-min window)
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(0, 5)
            .Select(i => TestHelpers.LoginFailure("10.0.0.3", timestamp: now.AddMinutes(-i * 2)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        // With a 5-min window and events at t=0,-2,-4,-6,-8 min,
        // only 3 events fall within any 5-min anchor window → no alert
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Different_IPs_Get_Independent_Alerts()
    {
        // Arrange: two IPs, each with 5 failures
        var now = DateTime.UtcNow;
        var events =
            Enumerable.Range(0, 5).Select(i => TestHelpers.LoginFailure("10.0.0.4", timestamp: now.AddSeconds(-i * 10)))
            .Concat(
            Enumerable.Range(0, 5).Select(i => TestHelpers.LoginFailure("10.0.0.5", timestamp: now.AddSeconds(-i * 10))))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().HaveCount(2);
        alerts.Select(a => a.SourceIP).Should().BeEquivalentTo(["10.0.0.4", "10.0.0.5"]);
    }

    [Fact]
    public async Task Empty_Event_List_Returns_No_Alerts()
    {
        var alerts = await _rule.EvaluateAsync([]);
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Alert_Description_Contains_IP_And_Count()
    {
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(0, 6)
            .Select(i => TestHelpers.LoginFailure("192.168.50.1", timestamp: now.AddSeconds(-i * 10)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().HaveCount(1);
        alerts[0].Description.Should().Contain("192.168.50.1");
        alerts[0].RecommendedAction.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Rule_Ignores_LoginSuccess_Events()
    {
        // Arrange: mix of 3 failures and 3 successes from same IP — should NOT alert
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(0, 3)
            .Select(i => TestHelpers.LoginFailure("10.1.1.1", timestamp: now.AddSeconds(-i * 5)))
            .Concat(Enumerable.Range(0, 3).Select(i => TestHelpers.LoginSuccess(timestamp: now.AddSeconds(-i * 5))))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Custom_Threshold_Of_3_Triggers_Alert()
    {
        var rule = new BruteForceRule(threshold: 3, windowSeconds: 300);
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(0, 3)
            .Select(i => TestHelpers.LoginFailure("10.5.5.5", timestamp: now.AddSeconds(-i * 5)))
            .ToList();

        var alerts = await rule.EvaluateAsync(events);

        alerts.Should().HaveCount(1);
    }
}
