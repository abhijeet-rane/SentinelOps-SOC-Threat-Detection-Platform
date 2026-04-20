using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Alert lifecycle management: CRUD, filtering, pagination, assignment, status transitions, SLA tracking.
/// </summary>
[ApiController]
[Asp.Versioning.ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]")]
[Authorize]
public class AlertsController : ControllerBase
{
    private readonly SOCDbContext _context;

    public AlertsController(SOCDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Get alerts with filtering, sorting, and pagination.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAlerts([FromQuery] AlertFilterDto filter)
    {
        var query = _context.Alerts
            .Include(a => a.AssignedAnalyst)
            .AsQueryable();

        // Apply filters
        if (filter.Severity.HasValue)
            query = query.Where(a => a.Severity == filter.Severity.Value);
        if (filter.Status.HasValue)
            query = query.Where(a => a.Status == filter.Status.Value);
        if (!string.IsNullOrEmpty(filter.DetectionRuleName))
            query = query.Where(a => a.DetectionRuleName == filter.DetectionRuleName);
        if (!string.IsNullOrEmpty(filter.AffectedUser))
            query = query.Where(a => a.AffectedUser != null && a.AffectedUser.Contains(filter.AffectedUser));
        if (!string.IsNullOrEmpty(filter.SourceIP))
            query = query.Where(a => a.SourceIP == filter.SourceIP);
        if (filter.AssignedTo.HasValue)
            query = query.Where(a => a.AssignedTo == filter.AssignedTo.Value);
        if (filter.From.HasValue)
            query = query.Where(a => a.CreatedAt >= filter.From.Value);
        if (filter.To.HasValue)
            query = query.Where(a => a.CreatedAt <= filter.To.Value);
        if (filter.SlaBreach == true)
            query = query.Where(a => a.SlaDeadline != null && DateTime.UtcNow > a.SlaDeadline && a.Status < AlertStatus.Resolved);

        // Sorting
        query = filter.SortBy?.ToLower() switch
        {
            "severity" => filter.SortDesc ? query.OrderByDescending(a => a.Severity) : query.OrderBy(a => a.Severity),
            "status" => filter.SortDesc ? query.OrderByDescending(a => a.Status) : query.OrderBy(a => a.Status),
            "title" => filter.SortDesc ? query.OrderByDescending(a => a.Title) : query.OrderBy(a => a.Title),
            _ => filter.SortDesc ? query.OrderByDescending(a => a.CreatedAt) : query.OrderBy(a => a.CreatedAt)
        };

        var totalCount = await query.CountAsync();

        var items = await query
            .Skip((filter.Page - 1) * filter.PageSize)
            .Take(filter.PageSize)
            .Select(a => MapAlertToDto(a))
            .ToListAsync();

        return Ok(new
        {
            success = true,
            data = new PagedResultDto<AlertDto>
            {
                Items = items,
                TotalCount = totalCount,
                Page = filter.Page,
                PageSize = filter.PageSize
            }
        });
    }

    /// <summary>
    /// Get a single alert by ID with full detail.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var alert = await _context.Alerts
            .Include(a => a.AssignedAnalyst)
            .FirstOrDefaultAsync(a => a.Id == id);

        if (alert == null)
            return NotFound(new { success = false, errors = new[] { "Alert not found" } });

        return Ok(new { success = true, data = MapAlertToDto(alert) });
    }

    /// <summary>
    /// Update alert status (lifecycle transition).
    /// NEW → IN_PROGRESS → ESCALATED → RESOLVED → CLOSED
    /// </summary>
    [HttpPatch("{id:guid}/status")]
    public async Task<IActionResult> UpdateStatus(Guid id, [FromBody] AlertStatusUpdateDto dto)
    {
        var alert = await _context.Alerts.FindAsync(id);
        if (alert == null)
            return NotFound(new { success = false, errors = new[] { "Alert not found" } });

        var oldStatus = alert.Status;
        alert.Status = dto.NewStatus;
        alert.UpdatedAt = DateTime.UtcNow;

        // Set lifecycle timestamps
        switch (dto.NewStatus)
        {
            case AlertStatus.InProgress when alert.AcknowledgedAt == null:
                alert.AcknowledgedAt = DateTime.UtcNow;
                break;
            case AlertStatus.Resolved:
                alert.ResolvedAt = DateTime.UtcNow;
                break;
            case AlertStatus.Closed:
                alert.ClosedAt = DateTime.UtcNow;
                break;
        }

        await _context.SaveChangesAsync();

        return Ok(new
        {
            success = true,
            data = new { alert.Id, OldStatus = oldStatus.ToString(), NewStatus = dto.NewStatus.ToString() },
            message = $"Alert status changed from {oldStatus} to {dto.NewStatus}"
        });
    }

    /// <summary>
    /// Assign an alert to an analyst.
    /// </summary>
    [HttpPatch("{id:guid}/assign")]
    public async Task<IActionResult> Assign(Guid id, [FromBody] AlertAssignDto dto)
    {
        var alert = await _context.Alerts.FindAsync(id);
        if (alert == null)
            return NotFound(new { success = false, errors = new[] { "Alert not found" } });

        var analyst = await _context.Users.FindAsync(dto.AnalystId);
        if (analyst == null)
            return BadRequest(new { success = false, errors = new[] { "Analyst not found" } });

        alert.AssignedTo = dto.AnalystId;
        alert.UpdatedAt = DateTime.UtcNow;

        // Auto-transition to InProgress if still New
        if (alert.Status == AlertStatus.New)
        {
            alert.Status = AlertStatus.InProgress;
            alert.AcknowledgedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();

        return Ok(new
        {
            success = true,
            message = $"Alert assigned to {analyst.Username}",
            data = new { alert.Id, AssignedTo = analyst.Username }
        });
    }

    /// <summary>
    /// Escalate an alert (sets status to Escalated).
    /// </summary>
    [HttpPatch("{id:guid}/escalate")]
    public async Task<IActionResult> Escalate(Guid id)
    {
        var alert = await _context.Alerts.FindAsync(id);
        if (alert == null)
            return NotFound(new { success = false, errors = new[] { "Alert not found" } });

        alert.Status = AlertStatus.Escalated;
        alert.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = "Alert escalated", data = new { alert.Id } });
    }

    /// <summary>
    /// Get alert statistics (counts by status, severity, SLA breaches).
    /// </summary>
    [HttpGet("stats")]
    public async Task<IActionResult> GetStats()
    {
        var alerts = await _context.Alerts.ToListAsync();

        var stats = new
        {
            Total = alerts.Count,
            ByStatus = new
            {
                New = alerts.Count(a => a.Status == AlertStatus.New),
                InProgress = alerts.Count(a => a.Status == AlertStatus.InProgress),
                Escalated = alerts.Count(a => a.Status == AlertStatus.Escalated),
                Resolved = alerts.Count(a => a.Status == AlertStatus.Resolved),
                Closed = alerts.Count(a => a.Status == AlertStatus.Closed)
            },
            BySeverity = new
            {
                Critical = alerts.Count(a => a.Severity == Severity.Critical),
                High = alerts.Count(a => a.Severity == Severity.High),
                Medium = alerts.Count(a => a.Severity == Severity.Medium),
                Low = alerts.Count(a => a.Severity == Severity.Low)
            },
            SlaBreaches = alerts.Count(a => a.SlaDeadline.HasValue && DateTime.UtcNow > a.SlaDeadline && a.Status < AlertStatus.Resolved),
            UnassignedCritical = alerts.Count(a => a.Severity >= Severity.High && a.AssignedTo == null && a.Status < AlertStatus.Resolved)
        };

        return Ok(new { success = true, data = stats });
    }

    private static AlertDto MapAlertToDto(Core.Entities.Alert a) => new()
    {
        Id = a.Id,
        Title = a.Title,
        Description = a.Description,
        Severity = a.Severity.ToString(),
        Status = a.Status.ToString(),
        DetectionRuleName = a.DetectionRuleName,
        MitreTechnique = a.MitreTechnique,
        MitreTactic = a.MitreTactic,
        AffectedUser = a.AffectedUser,
        AffectedDevice = a.AffectedDevice,
        SourceIP = a.SourceIP,
        RecommendedAction = a.RecommendedAction,
        AssignedAnalystName = a.AssignedAnalyst?.Username,
        AssignedTo = a.AssignedTo,
        IncidentId = a.IncidentId,
        DetectionRuleId = a.DetectionRuleId,
        EventId = a.EventId,
        SlaDeadline = a.SlaDeadline,
        AcknowledgedAt = a.AcknowledgedAt,
        ResolvedAt = a.ResolvedAt,
        ClosedAt = a.ClosedAt,
        CreatedAt = a.CreatedAt,
        UpdatedAt = a.UpdatedAt
    };
}
