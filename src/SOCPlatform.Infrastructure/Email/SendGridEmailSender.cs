using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;

namespace SOCPlatform.Infrastructure.Email;

/// <summary>
/// SendGrid-based email sender. Used in Production. Domain `wallystudio.in` is verified in SendGrid.
/// </summary>
public sealed class SendGridEmailSender : IEmailSender
{
    private readonly EmailOptions _options;
    private readonly ILogger<SendGridEmailSender> _logger;
    private readonly SendGridClient _client;

    public SendGridEmailSender(IOptions<EmailOptions> options, ILogger<SendGridEmailSender> logger)
    {
        _options = options.Value;
        _logger = logger;

        if (string.IsNullOrWhiteSpace(_options.SendGrid.ApiKey))
            throw new InvalidOperationException("SendGrid API key is not configured. Set SENDGRID_API_KEY env var.");

        _client = new SendGridClient(_options.SendGrid.ApiKey);
    }

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        var from = new EmailAddress(_options.FromAddress, _options.FromName);
        var to = new EmailAddress(message.To, message.ToName);
        var msg = MailHelper.CreateSingleEmail(
            from, to, message.Subject,
            plainTextContent: message.PlainTextBody ?? StripHtml(message.HtmlBody),
            htmlContent: message.HtmlBody);

        if (!string.IsNullOrEmpty(_options.ReplyTo))
            msg.ReplyTo = new EmailAddress(_options.ReplyTo);

        var response = await _client.SendEmailAsync(msg, cancellationToken);

        if ((int)response.StatusCode >= 400)
        {
            var body = await response.Body.ReadAsStringAsync(cancellationToken);
            _logger.LogError("SendGrid send failed {Status} for {To}: {Body}", response.StatusCode, message.To, body);
            throw new InvalidOperationException($"SendGrid send failed with status {response.StatusCode}");
        }

        _logger.LogInformation("Email sent via SendGrid to {To} subject={Subject}", message.To, message.Subject);
    }

    private static string StripHtml(string html) =>
        System.Text.RegularExpressions.Regex.Replace(html, "<.*?>", string.Empty);
}
