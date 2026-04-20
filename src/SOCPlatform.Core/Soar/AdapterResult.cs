namespace SOCPlatform.Core.Soar;

/// <summary>
/// Uniform result returned by every SOAR adapter call.
/// <see cref="IsSimulated"/> drives the "Simulated" badge in the dashboard
/// and the audit-trail entry distinguishes simulated from real actions.
/// </summary>
public sealed record AdapterResult(
    bool Success,
    string AdapterName,
    bool IsSimulated,
    string Action,
    string Target,
    string Message,
    int LatencyMs,
    Dictionary<string, object>? Metadata = null,
    string? ErrorDetail = null)
{
    public DateTime ExecutedAt { get; init; } = DateTime.UtcNow;

    public static AdapterResult Ok(string adapter, bool simulated, string action, string target, string message, int latencyMs, Dictionary<string, object>? meta = null)
        => new(true, adapter, simulated, action, target, message, latencyMs, meta);

    public static AdapterResult Fail(string adapter, bool simulated, string action, string target, string error, int latencyMs)
        => new(false, adapter, simulated, action, target, $"Action failed: {error}", latencyMs, ErrorDetail: error);
}
