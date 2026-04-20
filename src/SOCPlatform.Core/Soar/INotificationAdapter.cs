namespace SOCPlatform.Core.Soar;

/// <summary>
/// Outbound notifications to SOC manager / on-call analyst.
/// Real implementations: SendGrid (email) · Slack webhooks · Teams · PagerDuty.
/// </summary>
public interface INotificationAdapter
{
    string Name { get; }
    bool IsSimulated { get; }

    /// <summary>
    /// Send a notification with the given subject + body. Recipients vary per
    /// implementation (e.g., a configured SOC Manager mailbox, a Slack channel).
    /// </summary>
    Task<AdapterResult> NotifyAsync(NotificationRequest request, CancellationToken ct = default);
}

public sealed record NotificationRequest(
    string Subject,
    string HtmlBody,
    string? PlainTextBody,
    string Severity,        // "Critical" / "High" / "Medium" / "Low"
    Guid? AlertId,
    string? Recipient = null);
