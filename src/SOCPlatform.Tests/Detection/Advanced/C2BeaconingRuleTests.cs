using FluentAssertions;
using SOCPlatform.Core.Entities;
using SOCPlatform.Detection.Rules.Advanced;

namespace SOCPlatform.Tests.Detection.Advanced;

public class C2BeaconingRuleTests
{
    private static SecurityEvent Conn(DateTime ts, string src, string dst) => new()
    {
        EventAction = "NetworkConnection",
        SourceIP = src,
        DestinationIP = dst,
        AffectedDevice = "WRK-001",
        Timestamp = ts,
    };

    [Fact]
    public async Task Steady_60s_Beacon_To_Same_Destination_Fires_Critical_Alert()
    {
        var rule = new C2BeaconingRule(minConnections: 10, maxJitterRatio: 0.2, windowMinutes: 60);
        var start = new DateTime(2026, 4, 20, 12, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 12)
            .Select(i => Conn(start.AddSeconds(i * 60), "10.0.0.5", "1.2.3.4"))
            .ToList();

        var alerts = await rule.EvaluateAsync(events);

        alerts.Should().HaveCount(1);
        var a = alerts.Single();
        a.Severity.Should().Be(Core.Enums.Severity.Critical);
        a.MitreTechnique.Should().Be("T1071");
        a.SourceIP.Should().Be("10.0.0.5");
        a.Description.Should().Contain("jitter ratio");
    }

    [Fact]
    public async Task Highly_Variable_Intervals_Do_Not_Fire()
    {
        var rule = new C2BeaconingRule(minConnections: 10, maxJitterRatio: 0.2, windowMinutes: 60);
        var start = new DateTime(2026, 4, 20, 12, 0, 0, DateTimeKind.Utc);
        var rng = new Random(42);
        var events = Enumerable.Range(0, 12)
            .Select(i => Conn(start.AddSeconds(rng.Next(10, 600)), "10.0.0.5", "1.2.3.4"))
            .ToList();

        var alerts = await rule.EvaluateAsync(events);
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Fewer_Than_Threshold_Connections_Do_Not_Fire()
    {
        var rule = new C2BeaconingRule(minConnections: 10);
        var start = new DateTime(2026, 4, 20, 12, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 5)
            .Select(i => Conn(start.AddSeconds(i * 60), "10.0.0.5", "1.2.3.4"))
            .ToList();

        (await rule.EvaluateAsync(events)).Should().BeEmpty();
    }

    [Fact]
    public async Task Separate_Destinations_Get_Independent_Alerts()
    {
        var rule = new C2BeaconingRule(minConnections: 10, maxJitterRatio: 0.2);
        var start = new DateTime(2026, 4, 20, 12, 0, 0, DateTimeKind.Utc);
        var events = new List<SecurityEvent>();
        for (int i = 0; i < 12; i++) events.Add(Conn(start.AddSeconds(i * 60), "10.0.0.5", "1.2.3.4"));
        for (int i = 0; i < 12; i++) events.Add(Conn(start.AddSeconds(i * 60), "10.0.0.5", "5.6.7.8"));

        var alerts = await rule.EvaluateAsync(events);

        alerts.Should().HaveCount(2);
        alerts.Select(a => a.Title).Should().Contain(t => t.Contains("1.2.3.4"));
        alerts.Select(a => a.Title).Should().Contain(t => t.Contains("5.6.7.8"));
    }
}
