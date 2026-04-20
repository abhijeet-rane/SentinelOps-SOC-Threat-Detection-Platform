using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Core.Soar;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Jobs;

namespace SOCPlatform.Tests.Soar;

public class ApprovalTimeoutEscalationJobTests
{
    private static SOCDbContext NewDb()
    {
        var opts = new DbContextOptionsBuilder<SOCDbContext>()
            .UseInMemoryDatabase($"soar-job-{Guid.NewGuid()}").Options;
        return new SOCDbContext(opts);
    }

    private static (SOCDbContext db, ResponsePlaybook playbook, Alert alert) Seed()
    {
        var db = NewDb();
        var playbook = new ResponsePlaybook
        {
            Id = Guid.NewGuid(),
            Name = "Block bad IPs",
            ActionType = PlaybookActionType.BlockIp,
            RequiresApproval = true,
            IsActive = true
        };
        var alert = new Alert
        {
            Id = Guid.NewGuid(),
            Title = "Brute force",
            Description = "x",
            Severity = Severity.High,
            Status = AlertStatus.New,
            SourceIP = "1.2.3.4",
            DetectionRuleName = "BruteForceRule",
            CreatedAt = DateTime.UtcNow,
            SlaDeadline = DateTime.UtcNow.AddHours(4)
        };
        db.Set<ResponsePlaybook>().Add(playbook);
        db.Alerts.Add(alert);
        db.SaveChanges();
        return (db, playbook, alert);
    }

    private static ApprovalTimeoutEscalationJob NewJob(SOCDbContext db, INotificationAdapter notify, int timeoutMin = 30, int autoRejectMin = 0) =>
        new(db, notify,
            Options.Create(new SoarOptions { ApprovalTimeoutMinutes = timeoutMin, AutoRejectAfterMinutes = autoRejectMin }),
            NullLogger<ApprovalTimeoutEscalationJob>.Instance);

    [Fact]
    public async Task RunAsync_No_Stale_Approvals_Does_Nothing()
    {
        var (db, playbook, alert) = Seed();
        db.PlaybookExecutions.Add(new PlaybookExecution
        {
            Id = Guid.NewGuid(), PlaybookId = playbook.Id, AlertId = alert.Id,
            Status = "Pending", CreatedAt = DateTime.UtcNow.AddMinutes(-5) // fresh
        });
        await db.SaveChangesAsync();

        var notify = new Mock<INotificationAdapter>();
        await NewJob(db, notify.Object).RunAsync();

        notify.Verify(n => n.NotifyAsync(It.IsAny<NotificationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RunAsync_Stale_Pending_Triggers_One_Notification()
    {
        var (db, playbook, alert) = Seed();
        db.PlaybookExecutions.Add(new PlaybookExecution
        {
            Id = Guid.NewGuid(), PlaybookId = playbook.Id, AlertId = alert.Id,
            Status = "Pending", CreatedAt = DateTime.UtcNow.AddMinutes(-45) // > 30 min threshold
        });
        await db.SaveChangesAsync();

        var notify = new Mock<INotificationAdapter>();
        notify.Setup(n => n.NotifyAsync(It.IsAny<NotificationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AdapterResult.Ok("Email", false, "Notify", "soc@x", "sent", 100));

        await NewJob(db, notify.Object).RunAsync();

        notify.Verify(n => n.NotifyAsync(It.IsAny<NotificationRequest>(), It.IsAny<CancellationToken>()), Times.Once);
        var execution = await db.PlaybookExecutions.SingleAsync();
        execution.Result.Should().Contain("ESCALATED-PENDING-APPROVAL");
    }

    [Fact]
    public async Task RunAsync_Already_Escalated_Row_Does_Not_Renotify()
    {
        var (db, playbook, alert) = Seed();
        db.PlaybookExecutions.Add(new PlaybookExecution
        {
            Id = Guid.NewGuid(), PlaybookId = playbook.Id, AlertId = alert.Id,
            Status = "Pending", CreatedAt = DateTime.UtcNow.AddMinutes(-90),
            Result = "[ESCALATED-PENDING-APPROVAL] notified=True at=2026-04-20T11:00:00Z"
        });
        await db.SaveChangesAsync();

        var notify = new Mock<INotificationAdapter>();
        await NewJob(db, notify.Object).RunAsync();

        notify.Verify(n => n.NotifyAsync(It.IsAny<NotificationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RunAsync_AutoRejects_When_Past_Hard_Timeout()
    {
        var (db, playbook, alert) = Seed();
        db.PlaybookExecutions.Add(new PlaybookExecution
        {
            Id = Guid.NewGuid(), PlaybookId = playbook.Id, AlertId = alert.Id,
            Status = "Pending", CreatedAt = DateTime.UtcNow.AddHours(-3) // > 60 min hard limit below
        });
        await db.SaveChangesAsync();

        var notify = new Mock<INotificationAdapter>();
        await NewJob(db, notify.Object, timeoutMin: 30, autoRejectMin: 60).RunAsync();

        var execution = await db.PlaybookExecutions.SingleAsync();
        execution.Status.Should().Be("Rejected");
        execution.ErrorMessage.Should().Contain("Auto-rejected");
        notify.Verify(n => n.NotifyAsync(It.IsAny<NotificationRequest>(), It.IsAny<CancellationToken>()), Times.Never,
            "auto-rejected rows should not also be notified about");
    }

    [Fact]
    public async Task RunAsync_Approved_And_Completed_Are_Not_Touched()
    {
        var (db, playbook, alert) = Seed();
        db.PlaybookExecutions.AddRange(
            new PlaybookExecution { Id = Guid.NewGuid(), PlaybookId = playbook.Id, AlertId = alert.Id, Status = "Approved", CreatedAt = DateTime.UtcNow.AddHours(-1) },
            new PlaybookExecution { Id = Guid.NewGuid(), PlaybookId = playbook.Id, AlertId = alert.Id, Status = "Completed", CreatedAt = DateTime.UtcNow.AddHours(-2) },
            new PlaybookExecution { Id = Guid.NewGuid(), PlaybookId = playbook.Id, AlertId = alert.Id, Status = "Failed", CreatedAt = DateTime.UtcNow.AddHours(-2) });
        await db.SaveChangesAsync();

        var notify = new Mock<INotificationAdapter>();
        await NewJob(db, notify.Object).RunAsync();

        notify.Verify(n => n.NotifyAsync(It.IsAny<NotificationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
