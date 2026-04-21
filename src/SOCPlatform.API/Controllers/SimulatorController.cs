using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Admin-only red-team / attack-simulator endpoint. Inserts synthetic
/// SecurityEvents directly into the detection pipeline, letting the
/// DetectionEngine evaluate them on its next 15-second cycle just like
/// real agent-sourced events. Used by the AttackSim CLI.
///
/// Every injected event gets a <c>simulated:true</c> flag in Metadata + the
/// supplied scenario tag so testers can later filter their synthetic data out.
/// </summary>
[ApiController]
[Asp.Versioning.ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]")]
[Authorize(Roles = "System Administrator")]
public class SimulatorController : ControllerBase
{
    private readonly SOCDbContext _db;
    private readonly ILogger<SimulatorController> _logger;

    public SimulatorController(SOCDbContext db, ILogger<SimulatorController> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>Inject a batch of synthetic SecurityEvents.</summary>
    [HttpPost("inject")]
    public async Task<IActionResult> Inject([FromBody] SimulatorInjectRequest request, CancellationToken ct)
    {
        if (request.Events.Count == 0)
            return BadRequest(new { success = false, message = "No events supplied" });

        // First, synthesize a parent Log row for every injected event so the
        // FK from SecurityEvent.LogId resolves. One throwaway Log per batch.
        var parentLog = new Log
        {
            EndpointId  = Guid.Empty,
            Source      = "attacksim",
            EventType   = "SimulatedInjection",
            Severity    = "Informational",
            RawData     = JsonSerializer.Serialize(new { request.ScenarioTag, count = request.Events.Count }),
            Hostname    = "simulator",
            Timestamp   = DateTime.UtcNow,
            IngestedAt  = DateTime.UtcNow
        };
        _db.Logs.Add(parentLog);
        await _db.SaveChangesAsync(ct);

        var events = request.Events.Select(dto =>
        {
            var metadata = new Dictionary<string, object?>(dto.Metadata ?? new())
            {
                ["simulated"] = true,
                ["scenario"] = request.ScenarioTag
            };

            return new SecurityEvent
            {
                LogId            = parentLog.Id,
                EventCategory    = dto.EventCategory,
                EventAction      = dto.EventAction,
                Severity         = dto.Severity,
                SourceIP         = dto.SourceIP,
                DestinationIP    = dto.DestinationIP,
                DestinationPort  = dto.DestinationPort,
                AffectedUser     = dto.AffectedUser,
                AffectedDevice   = dto.AffectedDevice,
                FileHash         = dto.FileHash,
                IsThreatIntelMatch = dto.IsThreatIntelMatch,
                MitreTechnique   = dto.MitreTechnique,
                MitreTactic      = dto.MitreTactic,
                Metadata         = JsonSerializer.Serialize(metadata),
                Timestamp        = dto.Timestamp?.ToUniversalTime() ?? DateTime.UtcNow
            };
        }).ToList();

        _db.SecurityEvents.AddRange(events);
        await _db.SaveChangesAsync(ct);

        _logger.LogWarning(
            "[AttackSim] Injected {Count} events tag={Tag} first={First} last={Last}",
            events.Count, request.ScenarioTag, events[0].Id, events[^1].Id);

        return Ok(new
        {
            success = true,
            data = new SimulatorInjectResult
            {
                EventsInserted = events.Count,
                FirstEventId   = events[0].Id,
                LastEventId    = events[^1].Id,
                ScenarioTag    = request.ScenarioTag,
                InjectedAtUtc  = DateTime.UtcNow,
            }
        });
    }
}
