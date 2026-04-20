using FluentAssertions;
using SOCPlatform.Core.Entities;
using SOCPlatform.Detection.Rules.Advanced;

namespace SOCPlatform.Tests.Detection.Advanced;

public class DataExfiltrationRuleTests
{
    private static SecurityEvent UploadEvent(long bytes, string dstIp, DateTime ts, string? dstDomain = null) => new()
    {
        EventAction = "NetworkConnection",
        SourceIP = "10.0.0.5",
        DestinationIP = dstIp,
        AffectedDevice = "WRK-001",
        Metadata = dstDomain is null
            ? $"{{\"bytes_out\":{bytes}}}"
            : $"{{\"bytes_out\":{bytes},\"destination_domain\":\"{dstDomain}\"}}",
        Timestamp = ts,
    };

    [Fact]
    public async Task Volume_Over_100MB_Fires_Critical()
    {
        var rule = new DataExfiltrationRule(volumeThresholdBytes: 100L * 1024 * 1024);
        var now = DateTime.UtcNow;
        // 50 events of 3 MB each = 150 MB total
        var events = Enumerable.Range(0, 50)
            .Select(i => UploadEvent(3L * 1024 * 1024, "45.67.89.10", now.AddMinutes(i * 0.5)))
            .ToList();

        var alerts = await rule.EvaluateAsync(events);

        alerts.Should().ContainSingle(a => a.Title.Contains("45.67.89.10"));
        alerts.Single(a => a.Title.Contains("45.67.89.10")).Severity.Should().Be(Core.Enums.Severity.Critical);
    }

    [Fact]
    public async Task Low_Volume_Does_Not_Fire_Volume_Alert()
    {
        var rule = new DataExfiltrationRule();
        var events = new List<SecurityEvent>
        {
            UploadEvent(5L * 1024 * 1024, "1.1.1.1", DateTime.UtcNow)
        };
        (await rule.EvaluateAsync(events)).Should().BeEmpty();
    }

    [Fact]
    public async Task OffHours_CloudStorage_Upload_Fires()
    {
        var rule = new DataExfiltrationRule();
        // 02:00 UTC = off-hours
        var offHours = new DateTime(2026, 4, 20, 2, 0, 0, DateTimeKind.Utc);
        var events = new List<SecurityEvent>
        {
            UploadEvent(1024, "1.1.1.1", offHours, dstDomain: "dropbox.com")
        };

        var alerts = await rule.EvaluateAsync(events);

        alerts.Should().ContainSingle(a => a.Title.Contains("dropbox.com"));
    }

    [Fact]
    public async Task BusinessHours_CloudStorage_Upload_Does_Not_Fire()
    {
        var rule = new DataExfiltrationRule();
        var businessHours = new DateTime(2026, 4, 20, 14, 0, 0, DateTimeKind.Utc);
        var events = new List<SecurityEvent>
        {
            UploadEvent(1024, "1.1.1.1", businessHours, dstDomain: "dropbox.com")
        };

        (await rule.EvaluateAsync(events)).Should().BeEmpty();
    }
}
