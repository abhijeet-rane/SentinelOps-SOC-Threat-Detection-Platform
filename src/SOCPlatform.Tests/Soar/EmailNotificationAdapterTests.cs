using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Core.Soar;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Soar.Adapters;

namespace SOCPlatform.Tests.Soar;

public class EmailNotificationAdapterTests
{
    private static EmailNotificationAdapter Make(Mock<IEmailSender> emailMock, string? replyTo = "soc.manager@example.com")
    {
        var opts = Options.Create(new EmailOptions
        {
            Provider = "Smtp",
            FromAddress = "noreply@example.com",
            FromName = "SentinelOps",
            ReplyTo = replyTo
        });
        return new EmailNotificationAdapter(emailMock.Object, opts, NullLogger<EmailNotificationAdapter>.Instance);
    }

    [Fact]
    public async Task NotifyAsync_Sends_Email_To_Configured_ReplyTo_When_No_Recipient_Override()
    {
        var email = new Mock<IEmailSender>();
        email.Setup(e => e.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        var adapter = Make(email);

        var req = new NotificationRequest("Test subject", "<b>html</b>", "text", "Critical", Guid.NewGuid());
        var result = await adapter.NotifyAsync(req);

        result.Success.Should().BeTrue();
        result.IsSimulated.Should().BeFalse("real email adapter should NOT show simulated badge");
        result.Target.Should().Be("soc.manager@example.com");
        result.AdapterName.Should().Be("Email");

        email.Verify(e => e.SendAsync(
            It.Is<EmailMessage>(m => m.To == "soc.manager@example.com"
                                  && m.Subject.Contains("[SentinelOps · Critical]")
                                  && m.Subject.Contains("Test subject")),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task NotifyAsync_Uses_Override_Recipient_When_Provided()
    {
        var email = new Mock<IEmailSender>();
        email.Setup(e => e.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        var adapter = Make(email);

        var req = new NotificationRequest("S", "<p/>", null, "High", Guid.NewGuid(), Recipient: "oncall@example.com");
        var result = await adapter.NotifyAsync(req);

        result.Target.Should().Be("oncall@example.com");
        email.Verify(e => e.SendAsync(
            It.Is<EmailMessage>(m => m.To == "oncall@example.com"),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task NotifyAsync_Returns_Failed_When_No_Recipient_Configured()
    {
        var email = new Mock<IEmailSender>();
        var adapter = Make(email, replyTo: null);

        var req = new NotificationRequest("S", "<p/>", null, "Low", null);
        var result = await adapter.NotifyAsync(req);

        result.Success.Should().BeFalse();
        result.ErrorDetail.Should().Contain("No SOC-Manager recipient");
        email.Verify(e => e.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task NotifyAsync_Returns_Failed_When_EmailSender_Throws()
    {
        var email = new Mock<IEmailSender>();
        email.Setup(e => e.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("SMTP down"));
        var adapter = Make(email);

        var req = new NotificationRequest("S", "<p/>", null, "Critical", null);
        var result = await adapter.NotifyAsync(req);

        result.Success.Should().BeFalse();
        result.ErrorDetail.Should().Be("SMTP down");
    }
}
