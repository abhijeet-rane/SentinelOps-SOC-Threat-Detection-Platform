namespace SOCPlatform.API.Middleware;

/// <summary>
/// Enforces a maximum request body size (default 5MB) to prevent abuse.
/// </summary>
public class RequestSizeLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly long _maxBytes;

    public RequestSizeLimitMiddleware(RequestDelegate next, long maxBytes = 5 * 1024 * 1024)
    {
        _next = next;
        _maxBytes = maxBytes;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.ContentLength > _maxBytes)
        {
            context.Response.StatusCode = 413;
            await context.Response.WriteAsJsonAsync(new
            {
                success = false,
                errors = new[] { $"Request body exceeds the {_maxBytes / (1024 * 1024)}MB limit" }
            });
            return;
        }

        await _next(context);
    }
}
