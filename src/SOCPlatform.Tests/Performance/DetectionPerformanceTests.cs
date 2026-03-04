using System.Diagnostics;
using FluentAssertions;
using SOCPlatform.Core.Entities;
using SOCPlatform.Detection.Rules;

namespace SOCPlatform.Tests.Performance;

/// <summary>
/// Performance benchmarks for detection rule evaluation.
/// These are not strict performance tests (CI time variability) but serve
/// as regression guards for catastrophic slowdowns.
/// </summary>
public class DetectionPerformanceTests
{
    [Fact]
    public async Task BruteForce_Rule_Evaluates_10000_Events_Under_2_Seconds()
    {
        var rule = new BruteForceRule(threshold: 5, windowSeconds: 300);
        var now = DateTime.UtcNow;

        // 10,000 failed login events spread across 100 IPs
        var events = Enumerable.Range(0, 10_000)
            .Select(i => TestHelpers.LoginFailure(
                sourceIp: $"10.0.{i % 100}.1",
                user: $"user{i % 200}",
                timestamp: now.AddSeconds(-i % 300)))
            .ToList();

        var sw = Stopwatch.StartNew();
        var alerts = await rule.EvaluateAsync(events);
        sw.Stop();

        sw.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(2),
            because: "BruteForce rule should evaluate 10k events in under 2 seconds");
        alerts.Should().NotBeNull();
    }

    [Fact]
    public async Task PortScan_Rule_Evaluates_5000_Events_Under_1_Second()
    {
        var rule = new PortScanRule(portThreshold: 20, windowSeconds: 60);
        var now = DateTime.UtcNow;

        var events = Enumerable.Range(0, 5_000)
            .Select(i => TestHelpers.NetworkConnection(
                sourceIp: $"172.16.{i % 50}.1",
                destPort: (i % 1024) + 1,
                timestamp: now.AddSeconds(-i % 120)))
            .ToList();

        var sw = Stopwatch.StartNew();
        var alerts = await rule.EvaluateAsync(events);
        sw.Stop();

        sw.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(1),
            because: "PortScan rule should evaluate 5k events under 1 second");
        alerts.Should().NotBeNull();
    }

    [Fact]
    public async Task AllRules_Evaluate_1000_Events_Under_500ms()
    {
        var rules = new List<IDetectionRule>
        {
            new BruteForceRule(),
            new PortScanRule(),
            new PrivilegeEscalationRule(),
            new AccountEnumerationRule(),
            new AfterHoursActivityRule(),
            new SuspiciousHashRule(),
            new PolicyViolationRule(),
        };

        var now = DateTime.UtcNow;
        var actions = new[] { "LoginFailure", "ActiveConnections", "FileAccess", "LoginSuccess", "ProcessCreate" };
        var events = Enumerable.Range(0, 1_000)
            .Select(i => new SecurityEvent
            {
                EventCategory = i % 2 == 0 ? "Security" : "Network",
                EventAction = actions[i % 5],
                SourceIP = $"10.{i % 10}.{i % 10}.1",
                AffectedUser = $"user{i % 50}",
                AffectedDevice = $"PC-{i % 20}",
                DestinationPort = i % 2 == 1 ? (int?)(i % 1024 + 1) : null,
                IsThreatIntelMatch = i % 100 == 0,
                FileHash = i % 100 == 0 ? $"hash{i}" : null,
                Severity = "Medium",
                Timestamp = now.AddSeconds(-i),
            })
            .ToList();

        var sw = Stopwatch.StartNew();
        var allAlerts = new List<Alert>();
        foreach (var rule in rules)
            allAlerts.AddRange(await rule.EvaluateAsync(events));
        sw.Stop();

        sw.Elapsed.Should().BeLessThan(TimeSpan.FromMilliseconds(500),
            because: "All 7 rules should evaluate 1k events in under 500ms");
        allAlerts.Should().NotBeNull();
    }

    [Fact]
    public async Task AccountEnumeration_Rule_Evaluates_5000_Events_Under_1_Second()
    {
        var rule = new AccountEnumerationRule(threshold: 10, windowSeconds: 300);
        var now = DateTime.UtcNow;

        var events = Enumerable.Range(0, 5_000)
            .Select(i => TestHelpers.LoginFailure(
                sourceIp: $"192.168.{i % 30}.1",
                user: $"target{i % 150}",
                timestamp: now.AddSeconds(-i % 300)))
            .ToList();

        var sw = Stopwatch.StartNew();
        var alerts = await rule.EvaluateAsync(events);
        sw.Stop();

        sw.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(1));
        alerts.Should().NotBeNull();
    }
}
