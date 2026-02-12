using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.API.Middleware;

/// <summary>
/// Middleware that authenticates requests to agent ingestion endpoints using API keys.
/// API keys are sent via X-API-Key header and validated via HMAC-SHA256 against stored hashes.
/// </summary>
public class ApiKeyAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ApiKeyAuthenticationMiddleware> _logger;

    public ApiKeyAuthenticationMiddleware(RequestDelegate next, ILogger<ApiKeyAuthenticationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";

        // Only apply to agent ingestion endpoints
        if (!path.StartsWith("/api/logs/ingest", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        if (!context.Request.Headers.TryGetValue("X-API-Key", out var apiKeyHeader))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { success = false, errors = new[] { "API key is required" } });
            return;
        }

        var apiKey = apiKeyHeader.ToString();
        var keyHash = ComputeKeyHash(apiKey);

        using var scope = context.RequestServices.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();

        var storedKey = await db.ApiKeys
            .FirstOrDefaultAsync(k => k.KeyHash == keyHash && k.IsActive && !k.IsRevoked);

        if (storedKey == null)
        {
            _logger.LogWarning("Invalid API key attempted from {IP}", context.Connection.RemoteIpAddress);
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { success = false, errors = new[] { "Invalid or revoked API key" } });
            return;
        }

        // Check expiration
        if (storedKey.ExpiresAt.HasValue && storedKey.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Expired API key {KeyId} used from {IP}", storedKey.Id, context.Connection.RemoteIpAddress);
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { success = false, errors = new[] { "API key has expired" } });
            return;
        }

        // Check endpoint binding (allowed endpoints)
        if (!string.IsNullOrEmpty(storedKey.AllowedEndpoints))
        {
            var allowed = storedKey.AllowedEndpoints.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (!allowed.Any(ep => path.StartsWith(ep, StringComparison.OrdinalIgnoreCase)))
            {
                _logger.LogWarning("API key {KeyId} not authorized for endpoint {Path}", storedKey.Id, path);
                context.Response.StatusCode = 403;
                await context.Response.WriteAsJsonAsync(new { success = false, errors = new[] { "API key not authorized for this endpoint" } });
                return;
            }
        }

        // Update last used timestamp
        storedKey.LastUsedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        // Store API key info in HttpContext for downstream use
        context.Items["ApiKeyId"] = storedKey.Id;
        context.Items["ApiKeyName"] = storedKey.Name;

        await _next(context);
    }

    private static string ComputeKeyHash(string apiKey)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));
        return Convert.ToHexStringLower(hashBytes);
    }
}
