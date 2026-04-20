using FluentAssertions;
using SOCPlatform.Core.Entities;
using SOCPlatform.Detection.Rules.Advanced;

namespace SOCPlatform.Tests.Detection.Advanced;

public class DnsTunnelingRuleTests
{
    private static SecurityEvent DnsQuery(string domain, DateTime? ts = null) => new()
    {
        EventAction = "DnsQuery",
        SourceIP = "10.0.0.5",
        AffectedDevice = "WRK-001",
        Metadata = $"{{\"domain\":\"{domain}\"}}",
        Timestamp = ts ?? DateTime.UtcNow,
    };

    [Fact]
    public async Task Very_Long_Subdomain_Fires()
    {
        var longSub = new string('a', 60);
        var rule = new DnsTunnelingRule();
        var alerts = await rule.EvaluateAsync(new() { DnsQuery($"{longSub}.evil.com") });
        alerts.Should().HaveCount(1);
        alerts[0].Description.Should().Contain("subdomain length");
    }

    [Fact]
    public async Task High_Entropy_Subdomain_Fires()
    {
        // 20 base64-ish chars → entropy > 4 bits/char
        var rule = new DnsTunnelingRule();
        var alerts = await rule.EvaluateAsync(new() { DnsQuery("a1b2C3d4E5f6G7h8I9j0.attacker.com") });
        alerts.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Normal_Subdomain_Does_Not_Fire()
    {
        var rule = new DnsTunnelingRule();
        (await rule.EvaluateAsync(new() { DnsQuery("mail.google.com") })).Should().BeEmpty();
        (await rule.EvaluateAsync(new() { DnsQuery("cdn.microsoft.com") })).Should().BeEmpty();
    }

    [Fact]
    public async Task Volume_Burst_Fires()
    {
        var rule = new DnsTunnelingRule(volumePerMinuteThreshold: 20);
        var start = new DateTime(2026, 4, 20, 12, 0, 0, DateTimeKind.Utc);
        // 25 queries in 30 seconds to the same parent
        var events = Enumerable.Range(0, 25)
            .Select(i => DnsQuery($"sub{i}.exfil.net", start.AddSeconds(i)))
            .ToList();

        var alerts = await rule.EvaluateAsync(events);
        alerts.Should().Contain(a => a.Description.Contains("within one minute"));
    }
}
