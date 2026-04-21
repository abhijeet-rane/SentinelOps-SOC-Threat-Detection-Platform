using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Services;

/// <summary>
/// HTTP client for communicating with the SOC Platform API.
/// Supports API key authentication and HMAC-SHA256 request signing.
///
/// TLS validation:
///   • Default (production) — the platform CA chain is validated by .NET's
///     default <see cref="HttpClientHandler"/>. Any chain / expiry / hostname
///     error rejects the request.
///   • Pinned thumbprint (optional) — if a hex SHA-256 thumbprint is supplied
///     we pin strictly to that certificate, ignoring the PKI chain.
///   • Insecure (dev only) — if <c>allowInvalidCerts=true</c> we skip
///     validation entirely. This is strictly a local-dev affordance; a
///     WARN is logged on every construction so it can't hide.
/// </summary>
public class ApiClientService : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;
    private readonly string _baseUrl;

    public bool IsConnected { get; private set; }

    public ApiClientService(
        string baseUrl,
        string apiKey,
        string? pinnedThumbprintSha256 = null,
        bool allowInvalidCerts = false)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _apiKey = apiKey;

        var handler = new HttpClientHandler();

        if (allowInvalidCerts)
        {
            // Dev-only escape hatch. Fail loud so this is never a silent default.
            System.Diagnostics.Trace.TraceWarning(
                "[ApiClientService] TLS validation is DISABLED (allowInvalidCerts=true). " +
                "This is only safe for local development against self-signed certs.");
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }
        else if (!string.IsNullOrWhiteSpace(pinnedThumbprintSha256))
        {
            var expected = pinnedThumbprintSha256.Replace(":", "").Replace(" ", "");
            handler.ServerCertificateCustomValidationCallback =
                (_, cert, _, errors) => cert is not null && CertificateThumbprintMatches(cert, expected);
        }
        else
        {
            // Default: strict PKI validation. Any policy error → reject.
            handler.ServerCertificateCustomValidationCallback =
                (_, _, _, errors) => errors == SslPolicyErrors.None;
        }

        _httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri(_baseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };

        _httpClient.DefaultRequestHeaders.Add("X-API-Key", _apiKey);
    }

    /// <summary>
    /// Send a batch of logs to the API with HMAC request signing.
    /// </summary>
    public async Task<(bool Success, string? Error)> SendBatchAsync(BatchLogIngestionDto batch)
    {
        try
        {
            var json = JsonSerializer.Serialize(batch);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            // Add HMAC signature headers
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var path = "/api/logs/ingest";
            var bodyHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
            var signingString = $"{timestamp}POST{path}{bodyHash}";
            var signature = ComputeHmac(_apiKey, signingString);

            using var request = new HttpRequestMessage(HttpMethod.Post, path);
            request.Content = content;
            request.Headers.Add("X-Timestamp", timestamp);
            request.Headers.Add("X-Signature", signature);

            var response = await _httpClient.SendAsync(request);
            IsConnected = true;

            if (response.IsSuccessStatusCode)
            {
                return (true, null);
            }

            var errorBody = await response.Content.ReadAsStringAsync();
            return (false, $"HTTP {(int)response.StatusCode}: {errorBody}");
        }
        catch (HttpRequestException ex)
        {
            IsConnected = false;
            return (false, $"Connection error: {ex.Message}");
        }
        catch (TaskCanceledException)
        {
            IsConnected = false;
            return (false, "Request timed out");
        }
    }

    /// <summary>
    /// Check API health endpoint for connectivity.
    /// </summary>
    public async Task<bool> CheckHealthAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("/api/logs/health");
            IsConnected = response.IsSuccessStatusCode;
            return IsConnected;
        }
        catch
        {
            IsConnected = false;
            return false;
        }
    }

    private static bool CertificateThumbprintMatches(X509Certificate2 cert, string expectedHex)
    {
        var actual = Convert.ToHexString(SHA256.HashData(cert.RawData));
        return string.Equals(actual, expectedHex, StringComparison.OrdinalIgnoreCase);
    }

    private static string ComputeHmac(string key, string data)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var hmacBytes = HMACSHA256.HashData(keyBytes, dataBytes);
        return Convert.ToHexStringLower(hmacBytes);
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
        GC.SuppressFinalize(this);
    }
}
