using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SOCPlatform.Infrastructure.Observability;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// HTTP client that proxies requests to the Python ML microservice
/// running on localhost:8001. Handles event analysis, model training,
/// and health checks.
/// </summary>
public class MlIntegrationService
{
    private readonly HttpClient _http;
    private readonly SocMetrics? _metrics;
    private readonly ILogger<MlIntegrationService> _logger;
    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
    };

    public MlIntegrationService(HttpClient http, ILogger<MlIntegrationService> logger, SocMetrics? metrics = null)
    {
        _http = http;
        _metrics = metrics;
        _logger = logger;
    }

    /// <summary>
    /// Analyze a single event for anomalies via the ML service.
    /// </summary>
    public async Task<MlAnalyzeResult?> AnalyzeEventAsync(MlAnalyzeRequest request)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var response = await _http.PostAsJsonAsync("/api/ml/analyze", request, _jsonOpts);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<MlAnalyzeResult>(_jsonOpts);
            sw.Stop();
            _metrics?.MlInferenceDurationMs.Record(sw.Elapsed.TotalMilliseconds,
                new KeyValuePair<string, object?>("model", result?.ModelUsed ?? "auto"),
                new KeyValuePair<string, object?>("outcome", "ok"));
            return result;
        }
        catch (Exception ex)
        {
            sw.Stop();
            _metrics?.MlInferenceDurationMs.Record(sw.Elapsed.TotalMilliseconds,
                new KeyValuePair<string, object?>("model", "unknown"),
                new KeyValuePair<string, object?>("outcome", "error"));
            _logger.LogWarning(ex, "ML analysis request failed");
            return null;
        }
    }

    /// <summary>
    /// Trigger model training (optionally with historical event data).
    /// </summary>
    public async Task<MlTrainResult?> TriggerTrainingAsync(string model = "all", List<Dictionary<string, object>>? events = null)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var payload = new { model, events };
            var response = await _http.PostAsJsonAsync("/api/ml/train", payload, _jsonOpts);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<MlTrainResult>(_jsonOpts);
            sw.Stop();
            _metrics?.MlInferenceDurationMs.Record(sw.Elapsed.TotalMilliseconds,
                new KeyValuePair<string, object?>("model", model),
                new KeyValuePair<string, object?>("outcome", "train"));
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ML training request failed");
            return null;
        }
    }

    /// <summary>
    /// Get the health/status of the ML service and all models.
    /// </summary>
    public async Task<MlStatusResult?> GetStatusAsync()
    {
        try
        {
            return await _http.GetFromJsonAsync<MlStatusResult>("/api/ml/status", _jsonOpts);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ML status check failed — is the Python service running?");
            return null;
        }
    }
}

// ── DTOs for ML Service Communication ──────────────────

public class MlAnalyzeRequest
{
    public string EventCategory { get; set; } = string.Empty;
    public string EventAction { get; set; } = string.Empty;
    public string? SourceIp { get; set; }
    public string? Username { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public bool? Success { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

public class MlAnalyzeResult
{
    public bool IsAnomaly { get; set; }
    public double AnomalyScore { get; set; }
    public double Confidence { get; set; }
    public string? Reason { get; set; }
    public string ModelUsed { get; set; } = string.Empty;
    public Dictionary<string, object>? Details { get; set; }
}

public class MlTrainResult
{
    public string Status { get; set; } = string.Empty;
    public List<string> ModelsTrained { get; set; } = new();
    public Dictionary<string, object>? Stats { get; set; }
}

public class MlStatusResult
{
    public string Status { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public Dictionary<string, object>? Models { get; set; }
    public DateTime Timestamp { get; set; }
}
