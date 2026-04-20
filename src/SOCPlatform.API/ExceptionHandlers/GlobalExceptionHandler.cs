using System.Net;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SOCPlatform.API.Middleware;

namespace SOCPlatform.API.ExceptionHandlers;

/// <summary>
/// .NET 10 native IExceptionHandler. Returns RFC 7807 ProblemDetails with correlation id.
/// Replaces the legacy GlobalExceptionMiddleware.
/// </summary>
public sealed class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;
    private readonly IHostEnvironment _env;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger, IHostEnvironment env)
    {
        _logger = logger;
        _env = env;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext context, Exception exception, CancellationToken cancellationToken)
    {
        var (statusCode, title) = exception switch
        {
            UnauthorizedAccessException => (HttpStatusCode.Unauthorized,    "Access denied"),
            KeyNotFoundException        => (HttpStatusCode.NotFound,        "Resource not found"),
            ArgumentException           => (HttpStatusCode.BadRequest,      exception.Message),
            InvalidOperationException   => (HttpStatusCode.Conflict,        exception.Message),
            TimeoutException            => (HttpStatusCode.GatewayTimeout,  "Upstream timeout"),
            _                           => (HttpStatusCode.InternalServerError, "An unexpected error occurred")
        };

        _logger.LogError(exception,
            "Unhandled exception on {Method} {Path} → {Status}",
            context.Request.Method, context.Request.Path, (int)statusCode);

        var correlationId = context.Items[CorrelationIdMiddleware.HeaderName]?.ToString();

        var problem = new ProblemDetails
        {
            Status   = (int)statusCode,
            Title    = title,
            Type     = $"https://httpstatuses.io/{(int)statusCode}",
            Instance = context.Request.Path
        };
        if (correlationId is not null) problem.Extensions["correlationId"] = correlationId;
        if (_env.IsDevelopment())      problem.Extensions["exception"]     = exception.GetType().Name;

        context.Response.StatusCode  = (int)statusCode;
        context.Response.ContentType = "application/problem+json";
        await context.Response.WriteAsJsonAsync(problem, cancellationToken);

        return true;
    }
}
