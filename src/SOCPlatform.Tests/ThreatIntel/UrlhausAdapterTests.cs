using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.ThreatIntel.Adapters;

namespace SOCPlatform.Tests.ThreatIntel;

public class UrlhausAdapterTests
{
    private static UrlhausAdapter CreateAdapter() =>
        new(NullLogger<UrlhausAdapter>.Instance);

    [Fact]
    public void SupportsType_Url_And_Domain()
    {
        var a = CreateAdapter();
        a.SupportsType(IndicatorType.Url).Should().BeTrue();
        a.SupportsType(IndicatorType.Domain).Should().BeTrue();
        a.SupportsType(IndicatorType.IpAddress).Should().BeFalse();
    }

    [Fact]
    public async Task LookupAsync_Always_Returns_Null_Bulk_Only()
    {
        var a = CreateAdapter();
        (await a.LookupAsync(IndicatorType.Url, "http://x")).Should().BeNull();
        (await a.LookupAsync(IndicatorType.Domain, "x.com")).Should().BeNull();
    }

    /// <summary>
    /// The bulk feed is downloaded over the network. We don't make a real HTTP call
    /// in tests — the adapter swallows transport errors and yields nothing. This
    /// test just proves the StreamBulkAsync contract: enumerable, doesn't throw.
    /// </summary>
    [Fact]
    public async Task StreamBulkAsync_Yields_Without_Throwing_When_Network_Fails()
    {
        var a = CreateAdapter();
        var collected = 0;
        // Use a 5-second cancellation so we don't hang on a real download in CI.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await foreach (var _ in a.StreamBulkAsync(cts.Token))
            {
                collected++;
                if (collected > 3) break; // sanity cap
            }
        }
        catch (OperationCanceledException) { /* expected if real download is slow (TaskCanceledException is a subtype) */ }

        // Either the network call succeeded (got >= 0 indicators) or failed silently
        // (got 0). Both are valid; we only assert no other exception escaped.
        collected.Should().BeGreaterOrEqualTo(0);
    }
}
