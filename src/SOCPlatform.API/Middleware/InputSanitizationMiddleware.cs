using System.Text.RegularExpressions;
using System.Web;

namespace SOCPlatform.API.Middleware;

/// <summary>
/// Middleware that sanitizes incoming request data to prevent XSS and SQL injection.
/// Runs on all endpoints to provide a defense-in-depth layer.
/// </summary>
public partial class InputSanitizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<InputSanitizationMiddleware> _logger;

    public InputSanitizationMiddleware(RequestDelegate next, ILogger<InputSanitizationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Check query string parameters for common attack patterns
        foreach (var param in context.Request.Query)
        {
            if (ContainsSuspiciousPattern(param.Value!))
            {
                _logger.LogWarning("Suspicious query parameter blocked: {Key} from {IP}",
                    param.Key, context.Connection.RemoteIpAddress);
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new
                {
                    success = false,
                    errors = new[] { $"Query parameter '{param.Key}' contains potentially unsafe content" }
                });
                return;
            }
        }

        await _next(context);
    }

    private static bool ContainsSuspiciousPattern(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;

        var decoded = HttpUtility.UrlDecode(value);

        // XSS patterns
        if (ScriptTagPattern().IsMatch(decoded)) return true;
        if (EventHandlerPattern().IsMatch(decoded)) return true;
        if (JavascriptProtocolPattern().IsMatch(decoded)) return true;

        // SQL injection patterns
        if (SqlInjectionPattern().IsMatch(decoded)) return true;

        return false;
    }

    [GeneratedRegex(@"<\s*script", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptTagPattern();

    [GeneratedRegex(@"on\w+\s*=", RegexOptions.IgnoreCase)]
    private static partial Regex EventHandlerPattern();

    [GeneratedRegex(@"javascript\s*:", RegexOptions.IgnoreCase)]
    private static partial Regex JavascriptProtocolPattern();

    [GeneratedRegex(@"('|--|;)\s*(DROP|ALTER|DELETE|INSERT|UPDATE|EXEC|UNION|SELECT)\b", RegexOptions.IgnoreCase)]
    private static partial Regex SqlInjectionPattern();
}
