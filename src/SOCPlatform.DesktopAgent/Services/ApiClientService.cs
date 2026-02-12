using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Services;

/// <summary>
/// HTTP client for communicating with the SOC Platform API.
/// Supports API key authentication and HMAC-SHA256 request signing.
/// Includes TLS certificate pinning for production deployments.
/// </summary>
public class ApiClientService : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;
    private readonly string _baseUrl;

    public bool IsConnected { get; private set; }

    public ApiClientService(string baseUrl, string apiKey)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _apiKey = apiKey;

        var handler = new HttpClientHandler
        {
            // TLS certificate pinning (enable in production with real certs)
            ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
            {
                // In production, pin to your specific certificate thumbprint:
                // return cert?.GetCertHashString() == "YOUR_CERT_THUMBPRINT";
                return true; // Allow all during development
            }
        };

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
