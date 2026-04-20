using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Soar;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Soar;

/// <summary>
/// Shared helper used by every Simulated*Adapter to:
///   • generate realistic latency (50-200 ms by default)
///   • persist a SimulatedActionLog row (forensic timeline)
///   • build the AdapterResult uniformly
/// </summary>
public sealed class SimulatedActionRecorder
{
    private static readonly Random Rng = new();

    private readonly SOCDbContext _db;
    private readonly ILogger<SimulatedActionRecorder> _logger;

    public SimulatedActionRecorder(SOCDbContext db, ILogger<SimulatedActionRecorder> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task<AdapterResult> RecordAsync(
        string adapterName,
        string action,
        string target,
        string reason,
        Guid? alertId,
        Func<Task<(bool success, string message, Dictionary<string, object>? meta, string? err)>> simulatedWork,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        // Simulated wire latency — adapters use this to "feel" like a real network call
        await Task.Delay(Rng.Next(50, 200), ct);

        bool success;
        string message;
        Dictionary<string, object>? meta;
        string? err;
        try
        {
            (success, message, meta, err) = await simulatedWork();
        }
        catch (Exception ex)
        {
            success = false;
            message = $"Simulator threw: {ex.Message}";
            meta = null;
            err = ex.ToString();
        }

        sw.Stop();
        var latency = (int)sw.ElapsedMilliseconds;

        var payload = JsonSerializer.Serialize(new { reason, target, alertId, meta });
        _db.SimulatedActionLogs.Add(new SimulatedActionLog
        {
            AdapterName = adapterName,
            Action = action,
            Target = target,
            Reason = reason,
            Payload = payload,
            Success = success,
            ErrorDetail = err,
            LatencyMs = latency,
            ExecutedAt = DateTime.UtcNow,
            AlertId = alertId
        });
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation(
            "[SOAR Simulator] {Adapter} {Action} target={Target} success={Success} latency={Latency}ms",
            adapterName, action, target, success, latency);

        return success
            ? AdapterResult.Ok(adapterName, simulated: true, action, target, message, latency, meta)
            : AdapterResult.Fail(adapterName, simulated: true, action, target, err ?? message, latency);
    }
}
