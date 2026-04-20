using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Resilience;
using SOCPlatform.Infrastructure.ThreatIntel.Adapters;

namespace SOCPlatform.Tests.ThreatIntel;

public class AbuseIpDbAdapterTests
{
    private static AbuseIpDbAdapter CreateAdapter(IHttpClientFactory factory, string apiKey = "test-key")
    {
        var opts = Options.Create(new ThreatIntelOptions
        {
            AbuseIpDb = new AbuseIpDbOptions { ApiKey = apiKey, MaxConfidenceAge = 90 }
        });
        return new AbuseIpDbAdapter(factory, opts, NullLogger<AbuseIpDbAdapter>.Instance);
    }

    [Fact]
    public void SupportsType_Only_Ip()
    {
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.AbuseIpDbClient, HttpStatusCode.OK, "{}"));
        a.SupportsType(IndicatorType.IpAddress).Should().BeTrue();
        a.SupportsType(IndicatorType.Domain).Should().BeFalse();
        a.SupportsType(IndicatorType.FileHash).Should().BeFalse();
    }

    [Fact]
    public async Task Lookup_With_No_Api_Key_Returns_Null()
    {
        var a = CreateAdapter(
            HttpClientMockHelper.ForResponse(PolicyRegistry.AbuseIpDbClient, HttpStatusCode.OK, "{}"),
            apiKey: "");
        (await a.LookupAsync(IndicatorType.IpAddress, "1.2.3.4")).Should().BeNull();
    }

    [Fact]
    public async Task Lookup_Returns_Null_For_Unsupported_Type()
    {
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.AbuseIpDbClient, HttpStatusCode.OK, "{}"));
        (await a.LookupAsync(IndicatorType.Domain, "example.com")).Should().BeNull();
    }

    [Fact]
    public async Task Lookup_Returns_Null_When_Confidence_Score_Is_Zero()
    {
        const string body = """
        {"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":0,"countryCode":"US",
                 "totalReports":0,"numDistinctUsers":0,"isPublic":true}}
        """;
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.AbuseIpDbClient, HttpStatusCode.OK, body));
        (await a.LookupAsync(IndicatorType.IpAddress, "8.8.8.8")).Should().BeNull();
    }

    [Theory]
    [InlineData(95, "Critical")]
    [InlineData(80, "High")]
    [InlineData(60, "Medium")]
    [InlineData(20, "Low")]
    public async Task Lookup_Maps_Score_To_Threat_Level(int score, string expectedLevel)
    {
        var body =
            "{\"data\":{\"ipAddress\":\"1.2.3.4\",\"abuseConfidenceScore\":" + score + "," +
            "\"countryCode\":\"RU\",\"totalReports\":42,\"numDistinctUsers\":7,\"isPublic\":true," +
            "\"usageType\":\"Data Center/Web Hosting/Transit\",\"isp\":\"AS12345 Bad ISP\"," +
            "\"lastReportedAt\":\"2026-04-19T12:00:00+00:00\"}}";
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.AbuseIpDbClient, HttpStatusCode.OK, body));

        var hit = await a.LookupAsync(IndicatorType.IpAddress, "1.2.3.4");

        hit.Should().NotBeNull();
        hit!.ConfidenceScore.Should().Be(score);
        hit.ThreatLevel.Should().Be(expectedLevel);
        hit.Source.Should().Be("AbuseIPDB");
        hit.Value.Should().Be("1.2.3.4");
        hit.IndicatorType.Should().Be(IndicatorType.IpAddress);
        hit.GeoCountry.Should().Be("RU");
        hit.Asn.Should().Be("AS12345 Bad ISP");
    }

    [Fact]
    public async Task Lookup_Returns_Null_On_4xx_5xx()
    {
        var a = CreateAdapter(HttpClientMockHelper.ForResponse(PolicyRegistry.AbuseIpDbClient, HttpStatusCode.TooManyRequests, "{}"));
        (await a.LookupAsync(IndicatorType.IpAddress, "1.2.3.4")).Should().BeNull();
    }

    [Fact]
    public async Task Lookup_Sends_Ip_To_Check_Endpoint()
    {
        HttpRequestMessage? captured = null;
        var factory = HttpClientMockHelper.ForResponse(
            PolicyRegistry.AbuseIpDbClient,
            HttpStatusCode.OK, "{\"data\":{\"abuseConfidenceScore\":0}}",
            baseAddress: new Uri("https://api.abuseipdb.com/api/v2/"),
            onRequest: req => captured = req);
        var a = CreateAdapter(factory);

        await a.LookupAsync(IndicatorType.IpAddress, "9.9.9.9");

        captured.Should().NotBeNull();
        captured!.RequestUri!.AbsolutePath.Should().Contain("/check");
        captured.RequestUri.Query.Should().Contain("ipAddress=9.9.9.9");
    }
}
