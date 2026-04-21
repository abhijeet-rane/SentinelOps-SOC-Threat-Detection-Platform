using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SOCPlatform.AttackSim.Scenarios;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Detection.Rules;
using SOCPlatform.Detection.Rules.Advanced;

namespace SOCPlatform.Tests.AttackSim;

/// <summary>
/// Every attack scenario must produce events that actually trigger the
/// corresponding detection rule. We feed the scenario's output straight into
/// the production rule's EvaluateAsync and assert at least one alert comes
/// back — so the simulator can't silently drift out of sync with the
/// detection engine.
/// </summary>
public class AttackScenarioTests
{
    // Shared mapping of DTO → SecurityEvent so rules can consume them.
    private static SecurityEvent ToEvent(Core.DTOs.SyntheticSecurityEventDto d, long id) => new()
    {
        Id              = id,
        EventCategory   = d.EventCategory,
        EventAction     = d.EventAction,
        Severity        = d.Severity,
        SourceIP        = d.SourceIP,
        DestinationIP   = d.DestinationIP,
        DestinationPort = d.DestinationPort,
        AffectedUser    = d.AffectedUser,
        AffectedDevice  = d.AffectedDevice,
        FileHash        = d.FileHash,
        MitreTechnique  = d.MitreTechnique,
        MitreTactic     = d.MitreTactic,
        Metadata        = d.Metadata is null ? null : System.Text.Json.JsonSerializer.Serialize(d.Metadata),
        Timestamp       = d.Timestamp ?? DateTime.UtcNow,
    };

    private static List<SecurityEvent> EventsFor(IAttackScenario s) =>
        s.Build().Select((d, i) => ToEvent(d, i + 1)).ToList();

    [Fact]
    public async Task BruteForceScenario_Triggers_BruteForceRule()
    {
        var events = EventsFor(new BruteForceScenario());
        var alerts = await new BruteForceRule().EvaluateAsync(events);
        alerts.Should().NotBeEmpty();
        alerts[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public async Task PortScanScenario_Triggers_PortScanRule()
    {
        var events = EventsFor(new PortScanScenario());
        var alerts = await new PortScanRule().EvaluateAsync(events);
        alerts.Should().NotBeEmpty();
    }

    [Fact]
    public async Task PrivEscScenario_Triggers_PrivilegeEscalationRule()
    {
        var events = EventsFor(new PrivEscScenario());
        var alerts = await new PrivilegeEscalationRule().EvaluateAsync(events);
        alerts.Should().NotBeEmpty();
    }

    [Fact]
    public async Task C2BeaconScenario_Triggers_C2BeaconingRule()
    {
        var events = EventsFor(new C2BeaconScenario());
        var alerts = await new C2BeaconingRule().EvaluateAsync(events);
        alerts.Should().NotBeEmpty();
        alerts[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task DgaScenario_Triggers_DgaDetectionRule()
    {
        var events = EventsFor(new DgaScenario());
        var alerts = await new DgaDetectionRule().EvaluateAsync(events);
        alerts.Should().NotBeEmpty();
    }

    [Fact]
    public async Task DnsTunnelScenario_Triggers_DnsTunnelingRule()
    {
        var events = EventsFor(new DnsTunnelScenario());
        var alerts = await new DnsTunnelingRule().EvaluateAsync(events);
        alerts.Should().NotBeEmpty();
    }

    [Fact]
    public async Task LateralMovementScenario_Triggers_LateralMovementRule()
    {
        var events = EventsFor(new LateralMovementScenario());
        var alerts = await new LateralMovementRule().EvaluateAsync(events);
        alerts.Should().NotBeEmpty();
    }

    [Fact]
    public async Task DataExfilScenario_Triggers_DataExfiltrationRule()
    {
        var events = EventsFor(new DataExfilScenario());
        var alerts = await new DataExfiltrationRule().EvaluateAsync(events);
        alerts.Should().NotBeEmpty();
    }

    [Fact]
    public void Every_Scenario_Declares_Expected_Rules_And_Non_Empty_Events()
    {
        IAttackScenario[] all = [
            new BruteForceScenario(), new PortScanScenario(), new PrivEscScenario(),
            new C2BeaconScenario(), new DgaScenario(), new DnsTunnelScenario(),
            new LateralMovementScenario(), new DataExfilScenario()
        ];

        foreach (var s in all)
        {
            s.Name.Should().NotBeNullOrWhiteSpace();
            s.Description.Should().NotBeNullOrWhiteSpace();
            s.ExpectedRules.Should().NotBeEmpty($"{s.Name} must declare the rule(s) it targets");
            s.Build().Should().NotBeEmpty($"{s.Name} must produce at least one event");
        }
    }
}
