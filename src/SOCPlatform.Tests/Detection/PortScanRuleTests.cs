using FluentAssertions;
using SOCPlatform.Detection.Rules;

namespace SOCPlatform.Tests.Detection;

/// <summary>
/// Unit tests for PortScanRule.
/// Rule: ≥20 distinct destination ports from the same source IP within 60 seconds triggers a Medium alert.
/// </summary>
public class PortScanRuleTests
{
    private readonly PortScanRule _rule = new(portThreshold: 20, windowSeconds: 60);

    [Fact]
    public async Task Returns_Alert_When_20_Distinct_Ports_Within_Window()
    {
        var now = DateTime.UtcNow;
        // 20 connection events to distinct ports, all within 60s
        var events = Enumerable.Range(1, 20)
            .Select(port => TestHelpers.NetworkConnection("172.16.0.1", port, timestamp: now.AddSeconds(-port)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().HaveCount(1);
        alerts[0].SourceIP.Should().Be("172.16.0.1");
        alerts[0].Severity.Should().Be(Core.Enums.Severity.Medium);
        alerts[0].MitreTechnique.Should().Be("T1046");
        alerts[0].Title.Should().Contain("Port Scan");
    }

    [Fact]
    public async Task No_Alert_When_Below_Port_Threshold()
    {
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(1, 19)
            .Select(port => TestHelpers.NetworkConnection("172.16.0.2", port, timestamp: now.AddSeconds(-port)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task No_Alert_When_Many_Connections_To_Same_Port()
    {
        // 50 connections all to port 80 — not a scan
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(0, 50)
            .Select(i => TestHelpers.NetworkConnection("172.16.0.3", 80, timestamp: now.AddSeconds(-i)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task No_Alert_When_Ports_Spread_Outside_Window()
    {
        // 20 distinct ports but events span 5 minutes
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(1, 20)
            .Select(port => TestHelpers.NetworkConnection("172.16.0.4", port, timestamp: now.AddMinutes(-port)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        // Within any 60s window there are far fewer than 20 ports
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Handles_Events_Without_DestinationPort_Gracefully()
    {
        // Events missing DestinationPort should be filtered out, no crash
        var events = Enumerable.Range(0, 30)
            .Select(_ => TestHelpers.LoginFailure()) // No DestinationPort field
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Multiple_Sources_Get_Independent_Alerts()
    {
        var now = DateTime.UtcNow;
        var events =
            Enumerable.Range(1, 20).Select(p => TestHelpers.NetworkConnection("10.0.0.10", p, timestamp: now.AddSeconds(-p)))
            .Concat(Enumerable.Range(100, 20).Select(p => TestHelpers.NetworkConnection("10.0.0.11", p, timestamp: now.AddSeconds(-p % 59))))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts.Should().HaveCount(2);
        alerts.Select(a => a.SourceIP).Should().Contain(["10.0.0.10", "10.0.0.11"]);
    }

    [Fact]
    public async Task Empty_Input_Returns_No_Alerts()
    {
        var alerts = await _rule.EvaluateAsync([]);
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Alert_Contains_Recommended_Action()
    {
        var now = DateTime.UtcNow;
        var events = Enumerable.Range(1, 20)
            .Select(p => TestHelpers.NetworkConnection("10.9.9.9", p, timestamp: now.AddSeconds(-p)))
            .ToList();

        var alerts = await _rule.EvaluateAsync(events);

        alerts[0].RecommendedAction.Should().Contain("firewall");
    }
}
