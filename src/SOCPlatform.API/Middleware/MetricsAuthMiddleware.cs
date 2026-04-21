using System.Security.Cryptography;
using System.Text;

namespace SOCPlatform.API.Middleware;

/// <summary>
/// Token-gates the Prometheus <c>/metrics</c> scrape endpoint in Production.
///
/// Prometheus must send <c>Authorization: Bearer &lt;token&gt;</c> where
/// the token matches <c>Security:MetricsScrapeToken</c> (env:
/// <c>METRICS_SCRAPE_TOKEN</c>). Missing / mismatched tokens return 401.
///
/// In Development the check is skipped — local developers running the
/// stack don't need to wire up a token to scrape metrics.
/// </summary>
public class MetricsAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<MetricsAuthMiddleware> _logger;
    private readonly byte[]? _expectedToken;
    private readonly bool _enforced;

    public MetricsAuthMiddleware(
        RequestDelegate next,
        ILogger<MetricsAuthMiddleware> logger,
        IHostEnvironment env,
        IConfiguration config)
    {
        _next = next;
        _logger = logger;

        _enforced = !env.IsDevelopment();
        var token = config["Security:MetricsScrapeToken"];
        _expectedToken = string.IsNullOrWhiteSpace(token) ? null : Encoding.UTF8.GetBytes(token);

        if (_enforced && _expectedToken is null)
        {
            // Log once at startup so operators get a clear signal.
            _logger.LogError(
                "MetricsAuthMiddleware: /metrics is token-gated in {Env} but Security:MetricsScrapeToken is unset. " +
                "All scrape requests will be rejected until it is configured.",
                env.EnvironmentName);
        }
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_enforced)
        {
            await _next(context);
            return;
        }

        if (_expectedToken is null)
        {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsync("metrics endpoint not configured");
            return;
        }

        if (!context.Request.Headers.TryGetValue("Authorization", out var authHeader) ||
            authHeader.Count == 0 ||
            !authHeader[0]!.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = 401;
            context.Response.Headers["WWW-Authenticate"] = "Bearer realm=\"metrics\"";
            return;
        }

        var submitted = Encoding.UTF8.GetBytes(authHeader[0]!.Substring("Bearer ".Length).Trim());

        if (!CryptographicOperations.FixedTimeEquals(submitted, _expectedToken))
        {
            _logger.LogWarning(
                "Unauthorized /metrics scrape attempt from {IP}",
                context.Connection.RemoteIpAddress);
            context.Response.StatusCode = 401;
            return;
        }

        await _next(context);
    }
}
