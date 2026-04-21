using System.Text.RegularExpressions;
using System.Web;

namespace SOCPlatform.API.Middleware;

/// <summary>
/// SECONDARY defense-in-depth layer — NOT a primary input validation control.
///
/// Real input safety in this codebase comes from:
///   • EF Core parameterised queries (no raw SQL concatenation anywhere),
///   • FluentValidation on every DTO entering a controller,
///   • Output encoding at the React layer + CSP headers on responses.
///
/// This middleware only scans query strings for coarse XSS / SQLi patterns
/// and returns 400 on a match. Regex blocking is well-known to be bypassable
/// (e.g. via character-class substitution or encoding tricks) so operators
/// must NOT rely on it for safety. The value is logging: a legitimate user
/// never hits these patterns, so every block here is an IOC worth triaging.
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
