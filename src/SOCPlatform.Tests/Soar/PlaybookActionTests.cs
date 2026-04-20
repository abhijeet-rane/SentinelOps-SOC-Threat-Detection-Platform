using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Core.Soar;
using SOCPlatform.Detection.Playbooks;

namespace SOCPlatform.Tests.Soar;

public class PlaybookActionTests
{
    private static Mock<IAuditService> NewAudit()
    {
        var m = new Mock<IAuditService>();
        m.Setup(a => a.LogAsync(
            It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>())).Returns(Task.CompletedTask);
        return m;
    }

    private static Alert NewAlert(string? sourceIp = null, string? user = null, string? device = null)
        => new()
        {
            Id = Guid.NewGuid(),
            Title = "Test alert",
            Description = "x",
            Severity = Severity.High,
            Status = AlertStatus.New,
            SourceIP = sourceIp,
            AffectedUser = user,
            AffectedDevice = device,
            DetectionRuleName = "TestRule",
            CreatedAt = DateTime.UtcNow,
            SlaDeadline = DateTime.UtcNow.AddHours(4)
        };

    // ── BlockIpAction ────────────────────────────────────────────────────────

    [Fact]
    public async Task BlockIpAction_Skips_When_No_Source_Ip()
    {
        var firewall = new Mock<IFirewallAdapter>();
        var action = new BlockIpAction(firewall.Object, NewAudit().Object, NullLogger<BlockIpAction>.Instance);

        var result = await action.ExecuteAsync(NewAlert(sourceIp: null), null);

        result.Should().Contain("skipped");
        firewall.Verify(f => f.BlockIpAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task BlockIpAction_Calls_Firewall_Adapter_And_Audits()
    {
        var firewall = new Mock<IFirewallAdapter>();
        firewall.Setup(f => f.BlockIpAsync("1.2.3.4", It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AdapterResult.Ok("FW", true, "BlockIp", "1.2.3.4", "blocked", 100));
        var audit = NewAudit();
        var action = new BlockIpAction(firewall.Object, audit.Object, NullLogger<BlockIpAction>.Instance);

        var result = await action.ExecuteAsync(NewAlert(sourceIp: "1.2.3.4"), null);

        result.Should().Contain("[SIM · FW]").And.Contain("blocked");
        audit.Verify(a => a.LogAsync(
            It.IsAny<Guid?>(), "SOAR.BlockIp", "Alert", It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>()), Times.Once);
    }

    // ── LockAccountAction ────────────────────────────────────────────────────

    [Fact]
    public async Task LockAccountAction_Uses_Custom_Duration_From_Config()
    {
        var identity = new Mock<IIdentityAdapter>();
        identity.Setup(i => i.LockAccountAsync("alice", TimeSpan.FromMinutes(120), It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AdapterResult.Ok("ID", true, "LockAccount", "alice", "locked", 50));
        var action = new LockAccountAction(identity.Object, NewAudit().Object, NullLogger<LockAccountAction>.Instance);

        await action.ExecuteAsync(NewAlert(user: "alice"), actionConfig: "120");

        identity.Verify(i => i.LockAccountAsync("alice", TimeSpan.FromMinutes(120),
            It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── EscalateAlertAction ──────────────────────────────────────────────────

    [Fact]
    public async Task EscalateAlertAction_Sets_Status_To_Escalated_And_Audits_Old_New()
    {
        var audit = NewAudit();
        var action = new EscalateAlertAction(audit.Object, NullLogger<EscalateAlertAction>.Instance);
        var alert = NewAlert();
        alert.Status = AlertStatus.New;

        await action.ExecuteAsync(alert, null);

        alert.Status.Should().Be(AlertStatus.Escalated);
        audit.Verify(a => a.LogAsync(
            It.IsAny<Guid?>(), "SOAR.EscalateAlert", "Alert", It.IsAny<string?>(),
            "New", "Escalated", It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>()), Times.Once);
    }

    // ── 3 New Actions ────────────────────────────────────────────────────────

    [Fact]
    public async Task IsolateEndpointAction_Skips_When_No_Affected_Device()
    {
        var endpoint = new Mock<IEndpointAdapter>();
        var action = new IsolateEndpointAction(endpoint.Object, NewAudit().Object, NullLogger<IsolateEndpointAction>.Instance);

        var result = await action.ExecuteAsync(NewAlert(device: null), null);

        result.Should().Contain("skipped");
        endpoint.Verify(e => e.IsolateEndpointAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IsolateEndpointAction_Calls_Endpoint_Adapter()
    {
        var endpoint = new Mock<IEndpointAdapter>();
        endpoint.Setup(e => e.IsolateEndpointAsync("workstation-42", It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AdapterResult.Ok("EP", true, "IsolateEndpoint", "workstation-42", "isolated", 100));
        var action = new IsolateEndpointAction(endpoint.Object, NewAudit().Object, NullLogger<IsolateEndpointAction>.Instance);

        var result = await action.ExecuteAsync(NewAlert(device: "workstation-42"), null);

        result.Should().Contain("isolated");
        endpoint.Verify(e => e.IsolateEndpointAsync("workstation-42",
            It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DisableUserAction_Calls_Identity_DisableUser()
    {
        var identity = new Mock<IIdentityAdapter>();
        identity.Setup(i => i.DisableUserAsync("compromised", It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AdapterResult.Ok("ID", true, "DisableUser", "compromised", "disabled", 80));
        var action = new DisableUserAction(identity.Object, NewAudit().Object, NullLogger<DisableUserAction>.Instance);

        await action.ExecuteAsync(NewAlert(user: "compromised"), null);

        identity.Verify(i => i.DisableUserAsync("compromised",
            It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ResetCredentialsAction_Calls_Identity_ResetCredentials()
    {
        var identity = new Mock<IIdentityAdapter>();
        identity.Setup(i => i.ResetCredentialsAsync("phished", It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AdapterResult.Ok("ID", true, "ResetCredentials", "phished", "reset", 80));
        var action = new ResetCredentialsAction(identity.Object, NewAudit().Object, NullLogger<ResetCredentialsAction>.Instance);

        await action.ExecuteAsync(NewAlert(user: "phished"), null);

        identity.Verify(i => i.ResetCredentialsAsync("phished",
            It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task All_New_Actions_Have_Correct_ActionType()
    {
        var endpoint = Mock.Of<IEndpointAdapter>();
        var identity = Mock.Of<IIdentityAdapter>();
        var audit = NewAudit().Object;

        new IsolateEndpointAction(endpoint, audit, NullLogger<IsolateEndpointAction>.Instance)
            .ActionType.Should().Be(PlaybookActionType.IsolateEndpoint);
        new DisableUserAction(identity, audit, NullLogger<DisableUserAction>.Instance)
            .ActionType.Should().Be(PlaybookActionType.DisableUser);
        new ResetCredentialsAction(identity, audit, NullLogger<ResetCredentialsAction>.Instance)
            .ActionType.Should().Be(PlaybookActionType.ResetCredentials);

        await Task.CompletedTask;
    }
}
