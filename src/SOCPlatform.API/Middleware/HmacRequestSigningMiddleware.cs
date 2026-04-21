using System.Security.Cryptography;
using System.Text;

namespace SOCPlatform.API.Middleware;

/// <summary>
/// Validates HMAC-SHA256 request signatures on agent ingestion endpoints.
///
/// Agents sign requests with: <c>HMAC-SHA256(apiKey, timestamp + method + path + bodyHash)</c>
/// and send the result in the <c>X-Signature</c> header along with
/// <c>X-Timestamp</c> (Unix seconds) and <c>X-API-Key</c>.
///
/// The <c>Security:RequireHmacIngestion</c> config flag controls whether
/// missing headers are tolerated:
///   • <c>true</c> (default in Production / Staging) → requests missing
///     <c>X-Signature</c> or <c>X-Timestamp</c> on <c>/api/logs/ingest*</c>
///     are rejected with 401.
///   • <c>false</c> (default in Development) → they fall through, letting
///     operators test ingestion by hand without computing signatures.
///
/// Replay protection: the timestamp must be within ±5 minutes of server
/// time. A fixed-time comparison is used on the signature itself.
/// </summary>
public class HmacRequestSigningMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<HmacRequestSigningMiddleware> _logger;
    private readonly bool _requireSignature;
    private static readonly TimeSpan AllowedClockSkew = TimeSpan.FromMinutes(5);

    public HmacRequestSigningMiddleware(
        RequestDelegate next,
        ILogger<HmacRequestSigningMiddleware> logger,
        IHostEnvironment env,
        IConfiguration config)
    {
        _next = next;
        _logger = logger;

        // Default: require HMAC in every non-Development environment. An
        // explicit config value wins over the default.
        var explicitFlag = config.GetValue<bool?>("Security:RequireHmacIngestion");
        _requireSignature = explicitFlag ?? !env.IsDevelopment();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";

        // Only apply to agent ingestion endpoints.
        if (!path.StartsWith("/api/logs/ingest", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        var hasSignature = context.Request.Headers.TryGetValue("X-Signature", out var signatureHeader);
        var hasTimestamp = context.Request.Headers.TryGetValue("X-Timestamp", out var timestampHeader);

        if (!hasSignature || !hasTimestamp)
        {
            if (_requireSignature)
            {
                _logger.LogWarning(
                    "Rejecting ingestion request without HMAC headers from {IP} path={Path}",
                    context.Connection.RemoteIpAddress, path);
                await RejectAsync(context, 401, "X-Signature and X-Timestamp headers are required for ingestion");
                return;
            }

            // Development fallthrough — explicitly logged so nobody ships this accidentally.
            _logger.LogWarning(
                "HMAC headers missing on ingestion request from {IP}; allowing because Security:RequireHmacIngestion=false",
                context.Connection.RemoteIpAddress);
            await _next(context);
            return;
        }

        // Validate timestamp to prevent replay attacks.
        if (!long.TryParse(timestampHeader, out var unixTimestamp))
        {
            await RejectAsync(context, 400, "Invalid X-Timestamp header");
            return;
        }

        var requestTime = DateTimeOffset.FromUnixTimeSeconds(unixTimestamp);
        var drift = DateTimeOffset.UtcNow - requestTime;

        if (drift.Duration() > AllowedClockSkew)
        {
            _logger.LogWarning("Request signature expired: drift={DriftSeconds}s from {IP}",
                drift.TotalSeconds, context.Connection.RemoteIpAddress);
            await RejectAsync(context, 401, "Request timestamp outside allowed window");
            return;
        }

        // Read and buffer the body so downstream middleware can also read it.
        context.Request.EnableBuffering();
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        var bodyHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
        var signingString = $"{timestampHeader}{context.Request.Method}{path}{bodyHash}";

        // The API key (from X-API-Key header) is used as the HMAC secret.
        if (!context.Request.Headers.TryGetValue("X-API-Key", out var apiKey))
        {
            await RejectAsync(context, 401, "API key required for signed requests");
            return;
        }

        var expectedSignature = ComputeHmac(apiKey!, signingString);

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(signatureHeader!),
                Encoding.UTF8.GetBytes(expectedSignature)))
        {
            _logger.LogWarning("Invalid HMAC signature from {IP}", context.Connection.RemoteIpAddress);
            await RejectAsync(context, 401, "Invalid request signature");
            return;
        }

        await _next(context);
    }

    private static Task RejectAsync(HttpContext ctx, int status, string error)
    {
        ctx.Response.StatusCode = status;
        return ctx.Response.WriteAsJsonAsync(new { success = false, errors = new[] { error } });
    }

    private static string ComputeHmac(string key, string data)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var hmacBytes = HMACSHA256.HashData(keyBytes, dataBytes);
        return Convert.ToHexStringLower(hmacBytes);
    }
}
