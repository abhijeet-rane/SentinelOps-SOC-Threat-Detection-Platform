using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Core.Soar;
using SOCPlatform.Infrastructure.Configuration;

namespace SOCPlatform.Infrastructure.Soar.Adapters;

/// <summary>
/// Real notification adapter — sends to the configured SOC-Manager mailbox via
/// the existing IEmailSender (MailHog in dev / SendGrid in prod).
/// Recipient defaults to EmailOptions.ReplyTo if the request doesn't override.
/// </summary>
public sealed class EmailNotificationAdapter : INotificationAdapter
{
    public string Name => "Email";
    public bool IsSimulated => false; // SendGrid in prod, MailHog in dev — both are "real" delivery

    private readonly IEmailSender _email;
    private readonly EmailOptions _options;
    private readonly ILogger<EmailNotificationAdapter> _logger;

    public EmailNotificationAdapter(
        IEmailSender email,
        IOptions<EmailOptions> options,
        ILogger<EmailNotificationAdapter> logger)
    {
        _email = email;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<AdapterResult> NotifyAsync(NotificationRequest request, CancellationToken ct = default)
    {
        var recipient = !string.IsNullOrWhiteSpace(request.Recipient)
            ? request.Recipient
            : _options.ReplyTo;

        if (string.IsNullOrWhiteSpace(recipient))
            return AdapterResult.Fail(Name, false, "Notify", "(no recipient)", "No SOC-Manager recipient configured (set Email:ReplyTo)", 0);

        var sw = Stopwatch.StartNew();
        try
        {
            var subject = $"[SentinelOps · {request.Severity}] {request.Subject}";
            await _email.SendAsync(new EmailMessage(
                To: recipient,
                Subject: subject,
                HtmlBody: request.HtmlBody,
                PlainTextBody: request.PlainTextBody,
                ToName: "SOC Manager"), ct);

            sw.Stop();
            _logger.LogInformation("[SOAR] Notification email sent to {To} for alert {AlertId}", recipient, request.AlertId);

            return AdapterResult.Ok(Name, false, "Notify", recipient,
                $"Notification email sent to {recipient}",
                (int)sw.ElapsedMilliseconds,
                new Dictionary<string, object> { ["subject"] = subject, ["severity"] = request.Severity });
        }
        catch (Exception ex)
        {
            sw.Stop();
            _logger.LogError(ex, "[SOAR] Email send failed for alert {AlertId}", request.AlertId);
            return AdapterResult.Fail(Name, false, "Notify", recipient, ex.Message, (int)sw.ElapsedMilliseconds);
        }
    }
}
