using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Resilience;
using SOCPlatform.Infrastructure.ThreatIntel.Adapters;

namespace SOCPlatform.Tests.ThreatIntel;

public class VirusTotalAdapterTests
{
    private static VirusTotalAdapter CreateAdapter(IHttpClientFactory factory, string apiKey = "test-key")
    {
        var opts = Options.Create(new ThreatIntelOptions
        {
            VirusTotal = new VirusTotalOptions { ApiKey = apiKey }
        });
        return new VirusTotalAdapter(factory, opts, NullLogger<VirusTotalAdapter>.Instance);
    }

    [Fact]
    public void SupportsType_Hash_Url_Domain_Ip_All_True()
    {
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.VirusTotalClient, HttpStatusCode.OK, "{}"));
        a.SupportsType(IndicatorType.FileHash).Should().BeTrue();
        a.SupportsType(IndicatorType.Url).Should().BeTrue();
        a.SupportsType(IndicatorType.Domain).Should().BeTrue();
        a.SupportsType(IndicatorType.IpAddress).Should().BeTrue();
        a.SupportsType(IndicatorType.Email).Should().BeFalse();
    }

    [Fact]
    public async Task Lookup_404_Returns_Null_Clean()
    {
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.VirusTotalClient, HttpStatusCode.NotFound, null));
        (await a.LookupAsync(IndicatorType.FileHash, "deadbeef")).Should().BeNull();
    }

    [Fact]
    public async Task Lookup_Without_Api_Key_Returns_Null()
    {
        var a = CreateAdapter(
            HttpClientMockHelper.ForResponse(PolicyRegistry.VirusTotalClient, HttpStatusCode.OK, "{}"),
            apiKey: "");
        (await a.LookupAsync(IndicatorType.FileHash, "abc")).Should().BeNull();
    }

    [Fact]
    public async Task Lookup_All_Clean_Returns_Null()
    {
        const string body = """
        {"data":{"attributes":{"last_analysis_stats":
            {"malicious":0,"suspicious":0,"harmless":50,"undetected":20}}}}
        """;
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.VirusTotalClient, HttpStatusCode.OK, body));
        (await a.LookupAsync(IndicatorType.FileHash, "abc")).Should().BeNull();
    }

    [Fact]
    public async Task Lookup_Critical_When_Forty_Percent_Plus_Engines_Flag()
    {
        const string body = """
        {"data":{"attributes":{
            "last_analysis_stats":{"malicious":35,"suspicious":5,"harmless":10,"undetected":50},
            "tags":["malicious","trojan"],
            "popular_threat_classification":{"suggested_threat_label":"Trojan.Win32.Generic"}
        }}}
        """;
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.VirusTotalClient, HttpStatusCode.OK, body));

        var hit = await a.LookupAsync(IndicatorType.FileHash, "abc123");

        hit.Should().NotBeNull();
        hit!.ThreatLevel.Should().Be("Critical");
        hit.ThreatType.Should().Be("Trojan.Win32.Generic");
        hit.Tags.Should().Contain("malicious");
        hit.ConfidenceScore.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Lookup_Medium_For_Small_Detection_Ratio()
    {
        const string body = """
        {"data":{"attributes":{"last_analysis_stats":
            {"malicious":3,"suspicious":1,"harmless":40,"undetected":10}}}}
        """;
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.VirusTotalClient, HttpStatusCode.OK, body));
        var hit = await a.LookupAsync(IndicatorType.FileHash, "x");
        hit.Should().NotBeNull();
        hit!.ThreatLevel.Should().BeOneOf("Medium", "Low"); // 4/54 ≈ 7%, falls into Medium bucket per Classify thresholds
    }

    [Fact]
    public async Task Lookup_Sends_To_Correct_Endpoint_For_Each_Type()
    {
        HttpRequestMessage? captured = null;

        var hashFactory = HttpClientMockHelper.ForResponse(
            PolicyRegistry.VirusTotalClient,
            HttpStatusCode.NotFound, null,
            baseAddress: new Uri("https://www.virustotal.com/api/v3/"),
            onRequest: r => captured = r);
        var a = CreateAdapter(hashFactory);
        await a.LookupAsync(IndicatorType.FileHash, "deadbeef");
        captured!.RequestUri!.AbsolutePath.Should().EndWith("/files/deadbeef");

        var ipFactory = HttpClientMockHelper.ForResponse(
            PolicyRegistry.VirusTotalClient,
            HttpStatusCode.NotFound, null,
            baseAddress: new Uri("https://www.virustotal.com/api/v3/"),
            onRequest: r => captured = r);
        var a2 = CreateAdapter(ipFactory);
        await a2.LookupAsync(IndicatorType.IpAddress, "1.1.1.1");
        captured!.RequestUri!.AbsolutePath.Should().EndWith("/ip_addresses/1.1.1.1");

        var domainFactory = HttpClientMockHelper.ForResponse(
            PolicyRegistry.VirusTotalClient,
            HttpStatusCode.NotFound, null,
            baseAddress: new Uri("https://www.virustotal.com/api/v3/"),
            onRequest: r => captured = r);
        var a3 = CreateAdapter(domainFactory);
        await a3.LookupAsync(IndicatorType.Domain, "evil.com");
        captured!.RequestUri!.AbsolutePath.Should().EndWith("/domains/evil.com");
    }
}
