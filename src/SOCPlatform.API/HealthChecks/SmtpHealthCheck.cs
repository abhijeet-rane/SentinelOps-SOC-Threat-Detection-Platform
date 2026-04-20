using MailKit.Net.Smtp;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using SOCPlatform.Infrastructure.Configuration;

namespace SOCPlatform.API.HealthChecks;

/// <summary>
/// TCP-connects to the configured SMTP host (MailHog in dev). No auth, no message send.
/// </summary>
public sealed class SmtpHealthCheck : IHealthCheck
{
    private readonly EmailOptions _options;

    public SmtpHealthCheck(IOptions<EmailOptions> options) => _options = options.Value;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!_options.Provider.Equals("Smtp", StringComparison.OrdinalIgnoreCase))
            return HealthCheckResult.Healthy("Provider is SendGrid; SMTP check skipped");

        try
        {
            using var client = new SmtpClient();
            await client.ConnectAsync(
                _options.Smtp.Host, _options.Smtp.Port,
                MailKit.Security.SecureSocketOptions.None, cancellationToken);
            await client.DisconnectAsync(true, cancellationToken);
            return HealthCheckResult.Healthy($"SMTP at {_options.Smtp.Host}:{_options.Smtp.Port} reachable");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("SMTP unreachable", ex);
        }
    }
}
