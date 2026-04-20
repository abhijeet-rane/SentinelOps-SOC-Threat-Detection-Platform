using FluentAssertions;
using SOCPlatform.Core.Entities;
using SOCPlatform.Detection.Rules.Advanced;

namespace SOCPlatform.Tests.Detection.Advanced;

public class DgaDetectionRuleTests
{
    private static SecurityEvent DnsQuery(string domain) => new()
    {
        EventAction = "DnsQuery",
        SourceIP = "10.0.0.5",
        AffectedDevice = "WRK-001",
        Metadata = $"{{\"domain\":\"{domain}\"}}",
        Timestamp = DateTime.UtcNow,
    };

    [Theory]
    [InlineData("kq1zxqbgwvjx.top")]         // looks random
    [InlineData("aaaabbbbccccdddd.tk")]      // degenerate bigrams
    [InlineData("qxzzvbnmpqlkjrth.info")]    // low-probability bigram chain
    public async Task Random_Looking_Domains_Fire(string domain)
    {
        var rule = new DgaDetectionRule();
        var alerts = await rule.EvaluateAsync(new() { DnsQuery(domain) });

        alerts.Should().HaveCount(1, $"'{domain}' should be flagged");
        alerts[0].Description.Should().Contain("bigram");
        alerts[0].MitreTechnique.Should().Be("T1568.002");
    }

    [Theory]
    [InlineData("google.com")]
    [InlineData("microsoft.com")]
    [InlineData("wikipedia.org")]
    [InlineData("stackoverflow.com")]
    public async Task Legit_Domains_Do_Not_Fire(string domain)
    {
        var rule = new DgaDetectionRule();
        var alerts = await rule.EvaluateAsync(new() { DnsQuery(domain) });
        alerts.Should().BeEmpty($"'{domain}' should look like a real English word");
    }

    [Fact]
    public async Task Short_Domains_Skipped()
    {
        // min length default = 8 — "xzq.com" would otherwise score low
        var rule = new DgaDetectionRule();
        (await rule.EvaluateAsync(new() { DnsQuery("xzq.com") })).Should().BeEmpty();
    }

    [Fact]
    public void ExtractSecondLevelLabel_Strips_TLDs()
    {
        DgaDetectionRule.ExtractSecondLevelLabel("foo.example.com").Should().Be("example");
        DgaDetectionRule.ExtractSecondLevelLabel("example.com.").Should().Be("example");
        DgaDetectionRule.ExtractSecondLevelLabel("bare").Should().Be("bare");
    }
}
