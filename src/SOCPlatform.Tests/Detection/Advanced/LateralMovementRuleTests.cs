using FluentAssertions;
using SOCPlatform.Core.Entities;
using SOCPlatform.Detection.Rules.Advanced;

namespace SOCPlatform.Tests.Detection.Advanced;

public class LateralMovementRuleTests
{
    private static SecurityEvent Login(string user, string device, DateTime ts) => new()
    {
        EventAction = "LoginSuccess",
        AffectedUser = user,
        AffectedDevice = device,
        SourceIP = "10.0.0.5",
        Timestamp = ts
    };

    [Fact]
    public async Task User_Hitting_Three_Distinct_Hosts_In_Window_Fires()
    {
        var rule = new LateralMovementRule(minDistinctHosts: 3, windowMinutes: 30);
        var start = new DateTime(2026, 4, 20, 12, 0, 0, DateTimeKind.Utc);
        var events = new List<SecurityEvent>
        {
            Login("alice", "WRK-01", start),
            Login("alice", "SVR-02", start.AddMinutes(5)),
            Login("alice", "SVR-03", start.AddMinutes(10)),
        };

        var alerts = await rule.EvaluateAsync(events);

        alerts.Should().HaveCount(1);
        alerts[0].AffectedUser.Should().Be("alice");
        alerts[0].Description.Should().Contain("WRK-01").And.Contain("SVR-02").And.Contain("SVR-03");
    }

    [Fact]
    public async Task Two_Distinct_Hosts_Does_Not_Fire()
    {
        var rule = new LateralMovementRule(minDistinctHosts: 3);
        var start = DateTime.UtcNow;
        var events = new List<SecurityEvent>
        {
            Login("alice", "WRK-01", start),
            Login("alice", "SVR-02", start.AddMinutes(10)),
        };
        (await rule.EvaluateAsync(events)).Should().BeEmpty();
    }

    [Fact]
    public async Task Hosts_Outside_Window_Not_Counted()
    {
        var rule = new LateralMovementRule(minDistinctHosts: 3, windowMinutes: 30);
        var start = new DateTime(2026, 4, 20, 12, 0, 0, DateTimeKind.Utc);
        var events = new List<SecurityEvent>
        {
            Login("alice", "WRK-01", start),
            Login("alice", "SVR-02", start.AddMinutes(10)),
            Login("alice", "SVR-03", start.AddMinutes(45)), // outside 30-min window from first
        };
        (await rule.EvaluateAsync(events)).Should().BeEmpty();
    }

    [Fact]
    public async Task Different_Users_Get_Independent_Evaluation()
    {
        var rule = new LateralMovementRule(minDistinctHosts: 3);
        var t = DateTime.UtcNow;
        var events = new List<SecurityEvent>
        {
            Login("alice", "A", t), Login("alice", "B", t.AddMinutes(5)), Login("alice", "C", t.AddMinutes(10)),
            Login("bob",   "X", t), Login("bob",   "Y", t.AddMinutes(5)), Login("bob",   "Z", t.AddMinutes(10)),
        };

        var alerts = await rule.EvaluateAsync(events);

        alerts.Should().HaveCount(2);
        alerts.Select(a => a.AffectedUser).Should().BeEquivalentTo(new[] { "alice", "bob" });
    }
}
