using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim;

/// <summary>
/// Thin HTTP client wrapping the two SentinelOps endpoints the simulator needs:
/// login to get a JWT, then inject events. All responses are tolerant JSON
/// parsers — we don't fail hard on extra/missing fields, just on HTTP errors.
/// </summary>
public sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private string? _token;

    public ApiClient(string baseUrl)
    {
        _http = new HttpClient { BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/") };
    }

    public async Task LoginAsync(string username, string password, CancellationToken ct)
    {
        var resp = await _http.PostAsJsonAsync("api/v1/auth/login", new { username, password }, Json, ct);
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var data = doc.RootElement.GetProperty("data");
        _token = data.GetProperty("accessToken").GetString();
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token);
    }

    public async Task<SimulatorInjectResult> InjectAsync(SimulatorInjectRequest request, CancellationToken ct)
    {
        var resp = await _http.PostAsJsonAsync("api/v1/simulator/inject", request, Json, ct);
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var data = doc.RootElement.GetProperty("data");
        return new SimulatorInjectResult
        {
            EventsInserted = data.GetProperty("eventsInserted").GetInt32(),
            FirstEventId   = data.GetProperty("firstEventId").GetInt64(),
            LastEventId    = data.GetProperty("lastEventId").GetInt64(),
            ScenarioTag    = data.GetProperty("scenarioTag").GetString() ?? "",
            InjectedAtUtc  = data.GetProperty("injectedAtUtc").GetDateTime(),
        };
    }

    /// <summary>
    /// Returns DetectionRuleName + Severity for every alert created after <paramref name="since"/>.
    /// The alerts endpoint uses the same JWT as login.
    /// </summary>
    public async Task<IReadOnlyList<AlertMini>> GetAlertsSinceAsync(DateTime since, CancellationToken ct)
    {
        var resp = await _http.GetAsync("api/v1/alerts?pageSize=200&sortBy=createdAt&sortOrder=desc", ct);
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var items = doc.RootElement.GetProperty("data").GetProperty("items");

        var alerts = new List<AlertMini>();
        foreach (var item in items.EnumerateArray())
        {
            var createdAt = item.GetProperty("createdAt").GetDateTime();
            if (createdAt < since) continue;

            alerts.Add(new AlertMini(
                Title: item.GetProperty("title").GetString() ?? "",
                DetectionRuleName: item.TryGetProperty("detectionRuleName", out var rn) ? rn.GetString() : null,
                Severity: item.GetProperty("severity").GetString() ?? "",
                CreatedAt: createdAt));
        }
        return alerts;
    }

    public void Dispose() => _http.Dispose();
}

public sealed record AlertMini(string Title, string? DetectionRuleName, string Severity, DateTime CreatedAt);
