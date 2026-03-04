using FluentAssertions;
using SOCPlatform.Detection.Rules;

namespace SOCPlatform.Tests.Detection;

/// <summary>
/// Unit tests for AfterHoursActivityRule.
/// Rule: Sensitive operations (LoginSuccess, FileAccess, USBDeviceConnected, ProcessCreate)
/// outside 08:00-18:00 local time → Medium alert.
/// </summary>
public class AfterHoursRuleTests
{
    private readonly AfterHoursActivityRule _rule = new();

    [Fact]
    public async Task LoginSuccess_OffHours_Produces_Alert()
    {
        var ev = TestHelpers.LoginSuccess(user: "nightowl", timestamp: TestHelpers.OffHoursLocal());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().HaveCount(1);
        alerts[0].Severity.Should().Be(Core.Enums.Severity.Medium);
        alerts[0].MitreTechnique.Should().Be("T1078");
        alerts[0].Title.Should().Contain("After-Hours");
        alerts[0].AffectedUser.Should().Be("nightowl");
    }

    [Fact]
    public async Task LoginSuccess_BusinessHours_No_Alert()
    {
        var ev = TestHelpers.LoginSuccess(user: "worker", timestamp: TestHelpers.BusinessHoursUtc());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task FileAccess_OffHours_Produces_Alert()
    {
        var ev = TestHelpers.FileAccess(user: "bob", timestamp: TestHelpers.OffHoursLocal());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().HaveCount(1);
        alerts[0].AffectedUser.Should().Be("bob");
    }

    [Fact]
    public async Task NonSensitive_Action_No_Alert_Even_OffHours()
    {
        // LoginFailure is NOT in the sensitive actions set
        var ev = TestHelpers.LoginFailure(timestamp: TestHelpers.OffHoursLocal());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task USBDeviceConnected_OffHours_Produces_Alert()
    {
        var ev = new Core.Entities.SecurityEvent
        {
            EventCategory = "Endpoint",
            EventAction = "USBDeviceConnected",
            AffectedUser = "charlie",
            AffectedDevice = "LAPTOP-03",
            Severity = "Medium",
            Timestamp = TestHelpers.OffHoursLocal(),
        };
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().HaveCount(1);
        alerts[0].AffectedUser.Should().Be("charlie");
    }

    [Fact]
    public async Task Multiple_Off_Hours_Events_All_Produce_Alerts()
    {
        var offTime = TestHelpers.OffHoursLocal();
        var events = new[]
        {
            TestHelpers.LoginSuccess("u1", timestamp: offTime),
            TestHelpers.LoginSuccess("u2", timestamp: offTime.AddMinutes(1)),
            TestHelpers.LoginSuccess("u3", timestamp: offTime.AddMinutes(2)),
        };

        var alerts = await _rule.EvaluateAsync(events.ToList());

        alerts.Should().HaveCount(3);
    }

    [Fact]
    public async Task Empty_Events_Returns_No_Alerts()
    {
        var alerts = await _rule.EvaluateAsync([]);
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Alert_Contains_Event_Timestamp_Info()
    {
        var ev = TestHelpers.LoginSuccess("lateworker", timestamp: TestHelpers.OffHoursLocal());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts[0].Description.Should().Contain("lateworker");
        alerts[0].RecommendedAction.Should().NotBeNullOrEmpty();
    }
}
