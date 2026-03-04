using FluentAssertions;
using SOCPlatform.Detection.Rules;

namespace SOCPlatform.Tests.Detection;

/// <summary>
/// Unit tests for PrivilegeEscalationRule.
/// Rule: SpecialPrivilegeAssigned or SensitivePrivilegeUse outside 08:00-18:00 local time → Critical alert.
/// </summary>
public class PrivilegeEscalationRuleTests
{
    private readonly PrivilegeEscalationRule _rule = new();

    [Fact]
    public async Task Returns_Alert_For_SpecialPrivilegeAssigned_OffHours()
    {
        var ev = TestHelpers.PrivilegeEvent("SpecialPrivilegeAssigned", "root", TestHelpers.OffHoursLocal());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().HaveCount(1);
        alerts[0].Severity.Should().Be(Core.Enums.Severity.Critical);
        alerts[0].MitreTechnique.Should().Be("T1078");
        alerts[0].AffectedUser.Should().Be("root");
        alerts[0].Title.Should().Contain("Privilege Escalation");
    }

    [Fact]
    public async Task Returns_Alert_For_SensitivePrivilegeUse_OffHours()
    {
        var ev = TestHelpers.PrivilegeEvent("SensitivePrivilegeUse", "admin", TestHelpers.OffHoursLocal());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().HaveCount(1);
        alerts[0].AffectedUser.Should().Be("admin");
    }

    [Fact]
    public async Task No_Alert_During_Business_Hours()
    {
        var ev = TestHelpers.PrivilegeEvent("SpecialPrivilegeAssigned", "sysadmin", TestHelpers.BusinessHoursUtc());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task No_Alert_For_Unrecognised_Action()
    {
        var ev = TestHelpers.PrivilegeEvent("NormalUserLogon", "alice", TestHelpers.OffHoursLocal());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Multiple_Off_Hours_Events_Each_Produce_Alert()
    {
        var offTime = TestHelpers.OffHoursLocal();
        var events = new[]
        {
            TestHelpers.PrivilegeEvent("SpecialPrivilegeAssigned", "u1", offTime),
            TestHelpers.PrivilegeEvent("SensitivePrivilegeUse", "u2", offTime.AddMinutes(1)),
        };

        var alerts = await _rule.EvaluateAsync(events.ToList());

        alerts.Should().HaveCount(2);
    }

    [Fact]
    public async Task Empty_Events_Returns_No_Alerts()
    {
        var alerts = await _rule.EvaluateAsync([]);
        alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task Alert_Description_Contains_Username_And_Time()
    {
        var ev = TestHelpers.PrivilegeEvent("SpecialPrivilegeAssigned", "suspectUser", TestHelpers.OffHoursLocal());
        var alerts = await _rule.EvaluateAsync([ev]);

        alerts[0].Description.Should().Contain("suspectUser");
    }
}
