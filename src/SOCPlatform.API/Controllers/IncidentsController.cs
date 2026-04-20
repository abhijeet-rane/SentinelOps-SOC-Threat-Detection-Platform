using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Incident case management: CRUD, analyst notes, evidence attachments, timeline, root cause tracking.
/// </summary>
[ApiController]
[Asp.Versioning.ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]")]
[Authorize]
public class IncidentsController : ControllerBase
{
    private readonly SOCDbContext _context;

    public IncidentsController(SOCDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Get all incidents with alert counts.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        var query = _context.Incidents
            .Include(i => i.Alerts)
            .Include(i => i.AssignedAnalyst)
            .OrderByDescending(i => i.CreatedAt);

        var totalCount = await query.CountAsync();

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(i => new IncidentDto
            {
                Id = i.Id,
                Title = i.Title,
                Description = i.Description,
                Severity = i.Severity.ToString(),
                Status = i.Status.ToString(),
                RootCause = i.RootCause,
                ImpactAssessment = i.ImpactAssessment,
                AssignedAnalystName = i.AssignedAnalyst != null ? i.AssignedAnalyst.Username : null,
                AssignedAnalystId = i.AssignedAnalystId,
                AlertCount = i.Alerts.Count,
                CreatedAt = i.CreatedAt,
                ResolvedAt = i.ResolvedAt,
                ClosedAt = i.ClosedAt,
                UpdatedAt = i.UpdatedAt
            })
            .ToListAsync();

        return Ok(new
        {
            success = true,
            data = new PagedResultDto<IncidentDto>
            {
                Items = items,
                TotalCount = totalCount,
                Page = page,
                PageSize = pageSize
            }
        });
    }

    /// <summary>
    /// Get incident detail with alerts, notes, evidence, and timeline.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var incident = await _context.Incidents
            .Include(i => i.Alerts).ThenInclude(a => a.AssignedAnalyst)
            .Include(i => i.Notes).ThenInclude(n => n.Author)
            .Include(i => i.Evidence)
            .Include(i => i.AssignedAnalyst)
            .FirstOrDefaultAsync(i => i.Id == id);

        if (incident == null)
            return NotFound(new { success = false, errors = new[] { "Incident not found" } });

        var dto = new IncidentDto
        {
            Id = incident.Id,
            Title = incident.Title,
            Description = incident.Description,
            Severity = incident.Severity.ToString(),
            Status = incident.Status.ToString(),
            RootCause = incident.RootCause,
            ImpactAssessment = incident.ImpactAssessment,
            AssignedAnalystName = incident.AssignedAnalyst?.Username,
            AssignedAnalystId = incident.AssignedAnalystId,
            AlertCount = incident.Alerts.Count,
            CreatedAt = incident.CreatedAt,
            ResolvedAt = incident.ResolvedAt,
            ClosedAt = incident.ClosedAt,
            UpdatedAt = incident.UpdatedAt,
            Alerts = incident.Alerts.Select(a => new AlertDto
            {
                Id = a.Id,
                Title = a.Title,
                Severity = a.Severity.ToString(),
                Status = a.Status.ToString(),
                DetectionRuleName = a.DetectionRuleName,
                MitreTechnique = a.MitreTechnique,
                AffectedUser = a.AffectedUser,
                SourceIP = a.SourceIP,
                CreatedAt = a.CreatedAt,
                UpdatedAt = a.UpdatedAt
            }).ToList(),
            Notes = incident.Notes.OrderByDescending(n => n.CreatedAt).Select(n => new IncidentNoteDto
            {
                Id = n.Id,
                AuthorId = n.AuthorId,
                Content = n.Content,
                AuthorName = n.Author.Username,
                CreatedAt = n.CreatedAt
            }).ToList(),
            Evidence = incident.Evidence.OrderByDescending(e => e.UploadedAt).Select(e => new IncidentEvidenceDto
            {
                Id = e.Id,
                FileName = e.FileName,
                FileType = e.FileType,
                Hash = e.Hash,
                FileSizeBytes = e.FileSizeBytes,
                UploadedBy = e.UploadedBy,
                UploadedAt = e.UploadedAt
            }).ToList(),
            Timeline = BuildTimeline(incident)
        };

        return Ok(new { success = true, data = dto });
    }

    /// <summary>
    /// Create a new incident, optionally linking existing alerts.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateIncidentDto dto)
    {
        if (!Enum.TryParse<Severity>(dto.Severity, true, out var severity))
            severity = Severity.Medium;

        var incident = new Incident
        {
            Title = dto.Title,
            Description = dto.Description,
            Severity = severity
        };

        _context.Incidents.Add(incident);
        await _context.SaveChangesAsync();

        // Link alerts if provided
        if (dto.AlertIds.Count > 0)
        {
            var alerts = await _context.Alerts
                .Where(a => dto.AlertIds.Contains(a.Id))
                .ToListAsync();

            foreach (var alert in alerts)
            {
                alert.IncidentId = incident.Id;
            }
            await _context.SaveChangesAsync();
        }

        return CreatedAtAction(nameof(GetById), new { id = incident.Id },
            new { success = true, data = new { incident.Id }, message = "Incident created" });
    }

    /// <summary>
    /// Update incident fields (title, description, severity, status, root cause, impact, assignment).
    /// </summary>
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateIncidentDto dto)
    {
        var incident = await _context.Incidents.FindAsync(id);
        if (incident == null)
            return NotFound(new { success = false, errors = new[] { "Incident not found" } });

        if (dto.Title != null) incident.Title = dto.Title;
        if (dto.Description != null) incident.Description = dto.Description;
        if (dto.Severity.HasValue) incident.Severity = dto.Severity.Value;
        if (dto.RootCause != null) incident.RootCause = dto.RootCause;
        if (dto.ImpactAssessment != null) incident.ImpactAssessment = dto.ImpactAssessment;
        if (dto.AssignedAnalystId.HasValue) incident.AssignedAnalystId = dto.AssignedAnalystId.Value;

        if (dto.Status.HasValue)
        {
            incident.Status = dto.Status.Value;
            if (dto.Status == IncidentStatus.Resolved) incident.ResolvedAt = DateTime.UtcNow;
            if (dto.Status == IncidentStatus.Closed) incident.ClosedAt = DateTime.UtcNow;
        }

        incident.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = "Incident updated" });
    }

    /// <summary>
    /// Add an analyst note to an incident.
    /// </summary>
    [HttpPost("{id:guid}/notes")]
    public async Task<IActionResult> AddNote(Guid id, [FromBody] AddIncidentNoteDto dto)
    {
        var incident = await _context.Incidents.FindAsync(id);
        if (incident == null)
            return NotFound(new { success = false, errors = new[] { "Incident not found" } });

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userId, out var authorId))
            return Unauthorized();

        var note = new IncidentNote
        {
            IncidentId = id,
            AuthorId = authorId,
            Content = dto.Content
        };

        _context.Set<IncidentNote>().Add(note);
        incident.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetById), new { id },
            new { success = true, data = new { note.Id }, message = "Note added" });
    }

    /// <summary>
    /// Upload evidence attachment to an incident (metadata only — stores hash and file info).
    /// </summary>
    [HttpPost("{id:guid}/evidence")]
    public async Task<IActionResult> AddEvidence(Guid id, [FromBody] IncidentEvidenceUploadDto dto)
    {
        var incident = await _context.Incidents.FindAsync(id);
        if (incident == null)
            return NotFound(new { success = false, errors = new[] { "Incident not found" } });

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userId, out var uploaderId))
            return Unauthorized();

        var evidence = new IncidentEvidence
        {
            IncidentId = id,
            FileName = dto.FileName,
            FileType = dto.FileType,
            Hash = dto.Hash,
            FileSizeBytes = dto.FileSizeBytes,
            StoragePath = dto.StoragePath,
            UploadedBy = uploaderId
        };

        _context.Set<IncidentEvidence>().Add(evidence);
        incident.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetById), new { id },
            new { success = true, data = new { evidence.Id }, message = "Evidence attached" });
    }

    /// <summary>
    /// Get timeline for an incident (alerts, notes, evidence, status changes).
    /// </summary>
    [HttpGet("{id:guid}/timeline")]
    public async Task<IActionResult> GetTimeline(Guid id)
    {
        var incident = await _context.Incidents
            .Include(i => i.Alerts)
            .Include(i => i.Notes).ThenInclude(n => n.Author)
            .Include(i => i.Evidence)
            .FirstOrDefaultAsync(i => i.Id == id);

        if (incident == null)
            return NotFound(new { success = false, errors = new[] { "Incident not found" } });

        return Ok(new { success = true, data = BuildTimeline(incident) });
    }

    /// <summary>
    /// Link additional alerts to an existing incident.
    /// </summary>
    [HttpPost("{id:guid}/alerts")]
    public async Task<IActionResult> LinkAlerts(Guid id, [FromBody] List<Guid> alertIds)
    {
        var incident = await _context.Incidents.FindAsync(id);
        if (incident == null)
            return NotFound(new { success = false, errors = new[] { "Incident not found" } });

        var alerts = await _context.Alerts.Where(a => alertIds.Contains(a.Id)).ToListAsync();
        foreach (var alert in alerts)
        {
            alert.IncidentId = id;
        }

        incident.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = $"{alerts.Count} alert(s) linked to incident" });
    }

    /// <summary>
    /// Build a chronological timeline from incident events.
    /// </summary>
    private static List<TimelineEntryDto> BuildTimeline(Incident incident)
    {
        var timeline = new List<TimelineEntryDto>();

        // Incident creation
        timeline.Add(new TimelineEntryDto
        {
            Timestamp = incident.CreatedAt,
            Type = "IncidentCreated",
            Description = $"Incident '{incident.Title}' created (Severity: {incident.Severity})"
        });

        // Alerts
        foreach (var alert in incident.Alerts)
        {
            timeline.Add(new TimelineEntryDto
            {
                Timestamp = alert.CreatedAt,
                Type = "Alert",
                Description = $"Alert: {alert.Title} ({alert.Severity} – {alert.DetectionRuleName})"
            });
        }

        // Notes
        foreach (var note in incident.Notes)
        {
            timeline.Add(new TimelineEntryDto
            {
                Timestamp = note.CreatedAt,
                Type = "Note",
                Description = note.Content.Length > 100 ? note.Content[..100] + "..." : note.Content,
                Actor = note.Author?.Username
            });
        }

        // Evidence
        foreach (var evidence in incident.Evidence)
        {
            timeline.Add(new TimelineEntryDto
            {
                Timestamp = evidence.UploadedAt,
                Type = "Evidence",
                Description = $"Evidence uploaded: {evidence.FileName} ({evidence.FileType}, {evidence.FileSizeBytes} bytes)"
            });
        }

        // Resolution / Closure
        if (incident.ResolvedAt.HasValue)
        {
            timeline.Add(new TimelineEntryDto
            {
                Timestamp = incident.ResolvedAt.Value,
                Type = "StatusChange",
                Description = "Incident resolved"
            });
        }
        if (incident.ClosedAt.HasValue)
        {
            timeline.Add(new TimelineEntryDto
            {
                Timestamp = incident.ClosedAt.Value,
                Type = "StatusChange",
                Description = "Incident closed"
            });
        }

        return timeline.OrderBy(t => t.Timestamp).ToList();
    }
}

/// <summary>
/// DTO for evidence upload metadata.
/// </summary>
public class IncidentEvidenceUploadDto
{
    public string FileName { get; set; } = string.Empty;
    public string FileType { get; set; } = string.Empty;
    public string? Hash { get; set; }
    public long FileSizeBytes { get; set; }
    public string? StoragePath { get; set; }
}
