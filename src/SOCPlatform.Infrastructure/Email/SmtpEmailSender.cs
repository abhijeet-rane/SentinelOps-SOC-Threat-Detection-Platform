using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;

namespace SOCPlatform.Infrastructure.Email;

/// <summary>
/// SMTP-based email sender. Used in Development against MailHog (localhost:1025, no auth, no TLS).
/// </summary>
public sealed class SmtpEmailSender : IEmailSender
{
    private readonly EmailOptions _options;
    private readonly ILogger<SmtpEmailSender> _logger;

    public SmtpEmailSender(IOptions<EmailOptions> options, ILogger<SmtpEmailSender> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        var mime = new MimeMessage();
        mime.From.Add(new MailboxAddress(_options.FromName, _options.FromAddress));
        mime.To.Add(new MailboxAddress(message.ToName ?? message.To, message.To));
        if (!string.IsNullOrEmpty(_options.ReplyTo))
            mime.ReplyTo.Add(MailboxAddress.Parse(_options.ReplyTo));
        mime.Subject = message.Subject;

        var bodyBuilder = new BodyBuilder
        {
            HtmlBody = message.HtmlBody,
            TextBody = message.PlainTextBody ?? StripHtml(message.HtmlBody)
        };
        mime.Body = bodyBuilder.ToMessageBody();

        using var client = new SmtpClient();
        var secure = _options.Smtp.UseSsl ? SecureSocketOptions.StartTls : SecureSocketOptions.None;

        await client.ConnectAsync(_options.Smtp.Host, _options.Smtp.Port, secure, cancellationToken);
        if (!string.IsNullOrEmpty(_options.Smtp.UserName))
            await client.AuthenticateAsync(_options.Smtp.UserName, _options.Smtp.Password, cancellationToken);

        await client.SendAsync(mime, cancellationToken);
        await client.DisconnectAsync(true, cancellationToken);

        _logger.LogInformation("Email sent via SMTP to {To} subject={Subject}", message.To, message.Subject);
    }

    private static string StripHtml(string html) =>
        System.Text.RegularExpressions.Regex.Replace(html, "<.*?>", string.Empty);
}
