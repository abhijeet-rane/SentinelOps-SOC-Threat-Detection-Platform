namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Provider-agnostic email sender. Implementations: SMTP (dev/MailHog) or SendGrid (prod).
/// </summary>
public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}

public sealed record EmailMessage(
    string To,
    string Subject,
    string HtmlBody,
    string? PlainTextBody = null,
    string? ToName = null);
