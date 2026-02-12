using System.Security.Cryptography;
using System.Text;

namespace SOCPlatform.API.Middleware;

/// <summary>
/// Validates HMAC-SHA256 request signatures on agent ingestion endpoints.
/// Agents sign requests with: HMAC-SHA256(apiKey, timestamp + method + path + bodyHash).
/// Prevents replay attacks via a 5-minute timestamp window.
/// </summary>
public class HmacRequestSigningMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<HmacRequestSigningMiddleware> _logger;
    private static readonly TimeSpan AllowedClockSkew = TimeSpan.FromMinutes(5);

    public HmacRequestSigningMiddleware(RequestDelegate next, ILogger<HmacRequestSigningMiddleware> logger)
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

        // Skip if no signature header (API key auth is still required)
        if (!context.Request.Headers.TryGetValue("X-Signature", out var signatureHeader) ||
            !context.Request.Headers.TryGetValue("X-Timestamp", out var timestampHeader))
        {
            // Signature is optional during development; remove this fallthrough in production
            await _next(context);
            return;
        }

        // Validate timestamp to prevent replay attacks
        if (!long.TryParse(timestampHeader, out var unixTimestamp))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { success = false, errors = new[] { "Invalid X-Timestamp header" } });
            return;
        }

        var requestTime = DateTimeOffset.FromUnixTimeSeconds(unixTimestamp);
        var drift = DateTimeOffset.UtcNow - requestTime;

        if (drift.Duration() > AllowedClockSkew)
        {
            _logger.LogWarning("Request signature expired: drift={DriftSeconds}s from {IP}",
                drift.TotalSeconds, context.Connection.RemoteIpAddress);
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { success = false, errors = new[] { "Request timestamp outside allowed window" } });
            return;
        }

        // Read and buffer the body so downstream middleware can also read it
        context.Request.EnableBuffering();
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        // Compute body hash
        var bodyHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body)));

        // Build the signing string: timestamp + method + path + bodyHash
        var signingString = $"{timestampHeader}{context.Request.Method}{path}{bodyHash}";

        // The API key (from X-API-Key header) is used as the HMAC secret
        if (!context.Request.Headers.TryGetValue("X-API-Key", out var apiKey))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { success = false, errors = new[] { "API key required for signed requests" } });
            return;
        }

        var expectedSignature = ComputeHmac(apiKey!, signingString);

        if (!CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(signatureHeader!),
            Encoding.UTF8.GetBytes(expectedSignature)))
        {
            _logger.LogWarning("Invalid HMAC signature from {IP}", context.Connection.RemoteIpAddress);
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { success = false, errors = new[] { "Invalid request signature" } });
            return;
        }

        await _next(context);
    }

    private static string ComputeHmac(string key, string data)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var hmacBytes = HMACSHA256.HashData(keyBytes, dataBytes);
        return Convert.ToHexStringLower(hmacBytes);
    }
}
