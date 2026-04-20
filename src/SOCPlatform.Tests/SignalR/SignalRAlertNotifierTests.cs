using FluentAssertions;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SOCPlatform.API.Hubs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Tests.SignalR;

public class SignalRAlertNotifierTests
{
    private static (SignalRAlertNotifier notifier, Mock<IClientProxy> clientProxy, Mock<IHubClients> hubClients)
        CreateNotifier()
    {
        var clientProxy = new Mock<IClientProxy>();
        var hubClients  = new Mock<IHubClients>();
        hubClients.SetupGet(h => h.All).Returns(clientProxy.Object);

        var hub = new Mock<IHubContext<AlertHub>>();
        hub.SetupGet(h => h.Clients).Returns(hubClients.Object);

        var notifier = new SignalRAlertNotifier(hub.Object, NullLogger<SignalRAlertNotifier>.Instance);
        return (notifier, clientProxy, hubClients);
    }

    private static Alert MakeAlert(string title = "Test", Severity sev = Severity.High) => new()
    {
        Id = Guid.NewGuid(),
        Title = title,
        Description = "desc",
        Severity = sev,
        Status = AlertStatus.New,
        DetectionRuleName = "TestRule",
        CreatedAt = DateTime.UtcNow,
        SlaDeadline = DateTime.UtcNow.AddHours(4),
    };

    [Fact]
    public async Task BroadcastAlertAsync_Sends_Single_Event_Named_AlertNew()
    {
        var (n, client, _) = CreateNotifier();

        await n.BroadcastAlertAsync(MakeAlert("Brute force"));

        client.Verify(c => c.SendCoreAsync(
            AlertHub.Events.AlertNew,
            It.Is<object?[]>(args => args.Length == 1),
            It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task BroadcastAlertsAsync_Sends_One_Batch_Event_Regardless_Of_Count()
    {
        var (n, client, _) = CreateNotifier();
        var alerts = new[] { MakeAlert("a"), MakeAlert("b"), MakeAlert("c") };

        await n.BroadcastAlertsAsync(alerts);

        client.Verify(c => c.SendCoreAsync(
            AlertHub.Events.AlertBatch,
            It.IsAny<object?[]>(),
            It.IsAny<CancellationToken>()),
            Times.Once, "batch should be a single SendAsync call");

        client.Verify(c => c.SendCoreAsync(
            AlertHub.Events.AlertNew,
            It.IsAny<object?[]>(),
            It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task BroadcastAlertsAsync_Empty_List_Sends_Nothing()
    {
        var (n, client, _) = CreateNotifier();
        await n.BroadcastAlertsAsync(Array.Empty<Alert>());

        client.Verify(c => c.SendCoreAsync(
            It.IsAny<string>(), It.IsAny<object?[]>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task BroadcastAlertAsync_Swallows_SignalR_Failures()
    {
        var (n, client, _) = CreateNotifier();
        client.Setup(c => c.SendCoreAsync(
            It.IsAny<string>(), It.IsAny<object?[]>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("redis backplane down"));

        // Must NOT throw — detection pipeline must be shielded.
        var act = () => n.BroadcastAlertAsync(MakeAlert());
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task BroadcastAlertsAsync_Passes_Dto_With_Expected_Fields()
    {
        var (n, client, _) = CreateNotifier();
        object? captured = null;
        client.Setup(c => c.SendCoreAsync(
                It.IsAny<string>(), It.IsAny<object?[]>(), It.IsAny<CancellationToken>()))
            .Callback((string _, object?[] args, CancellationToken _) => captured = args[0])
            .Returns(Task.CompletedTask);

        var alert = MakeAlert("RCE Attempt", Severity.Critical);
        alert.SourceIP = "1.2.3.4";
        alert.AffectedUser = "alice";

        await n.BroadcastAlertsAsync(new[] { alert });

        captured.Should().NotBeNull();
        var json = System.Text.Json.JsonSerializer.Serialize(captured);
        json.Should().Contain("\"alerts\"");
        json.Should().Contain("RCE Attempt");
        json.Should().Contain("Critical");
        json.Should().Contain("1.2.3.4");
        json.Should().Contain("alice");
    }
}
