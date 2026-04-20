using System.ComponentModel.DataAnnotations;

namespace SOCPlatform.Infrastructure.Configuration;

public sealed class EmailOptions
{
    public const string SectionName = "Email";

    /// <summary>"Smtp" (dev / MailHog) or "SendGrid" (prod). Defaults to Smtp.</summary>
    [Required] public string Provider { get; init; } = "Smtp";

    [Required, EmailAddress] public string FromAddress { get; init; } = string.Empty;
    [Required] public string FromName { get; init; } = string.Empty;
    [EmailAddress] public string? ReplyTo { get; init; }

    public SmtpOptions Smtp { get; init; } = new();
    public SendGridOptions SendGrid { get; init; } = new();
}

public sealed class SmtpOptions
{
    public string Host { get; init; } = "localhost";
    [Range(1, 65535)] public int Port { get; init; } = 1025;
    public bool UseSsl { get; init; } = false;
    public string? UserName { get; init; }
    public string? Password { get; init; }
}

public sealed class SendGridOptions
{
    public string ApiKey { get; init; } = string.Empty;
}
