using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// SOAR Playbook management: CRUD, execution history, analyst approval workflow.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class PlaybooksController : ControllerBase
{
    private readonly SOCDbContext _context;

    public PlaybooksController(SOCDbContext context)
    {
        _context = context;
    }

    // ── Playbook CRUD ──

    /// <summary>
    /// Get all playbooks with execution stats.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var playbooks = await _context.Set<ResponsePlaybook>()
            .Include(p => p.Executions)
            .OrderBy(p => p.Name)
            .ToListAsync();

        var result = playbooks.Select(p => new
        {
            p.Id,
            p.Name,
            p.Description,
            ActionType = p.ActionType.ToString(),
            p.RequiresApproval,
            p.IsActive,
            p.TriggerCondition,
            p.CreatedAt,
            Stats = new
            {
                TotalExecutions = p.Executions.Count,
                Completed = p.Executions.Count(e => e.Status == "Completed"),
                Failed = p.Executions.Count(e => e.Status == "Failed"),
                Pending = p.Executions.Count(e => e.Status == "Pending"),
                Approved = p.Executions.Count(e => e.Status == "Approved")
            }
        });

        return Ok(new { success = true, data = result });
    }

    /// <summary>
    /// Get a specific playbook by ID with execution history.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var playbook = await _context.Set<ResponsePlaybook>()
            .Include(p => p.Executions).ThenInclude(e => e.Alert)
            .FirstOrDefaultAsync(p => p.Id == id);

        if (playbook == null)
            return NotFound(new { success = false, errors = new[] { "Playbook not found" } });

        return Ok(new
        {
            success = true,
            data = new
            {
                playbook.Id,
                playbook.Name,
                playbook.Description,
                ActionType = playbook.ActionType.ToString(),
                playbook.ActionConfig,
                playbook.RequiresApproval,
                playbook.IsActive,
                playbook.TriggerCondition,
                playbook.CreatedAt,
                Executions = playbook.Executions.OrderByDescending(e => e.CreatedAt).Take(50).Select(e => new
                {
                    e.Id,
                    e.AlertId,
                    AlertTitle = e.Alert.Title,
                    e.Status,
                    e.Result,
                    e.ErrorMessage,
                    e.CreatedAt,
                    e.ApprovedAt,
                    e.ExecutedAt,
                    e.CompletedAt
                })
            }
        });
    }

    /// <summary>
    /// Create a new playbook.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> Create([FromBody] PlaybookCreateDto dto)
    {
        if (!Enum.TryParse<PlaybookActionType>(dto.ActionType, true, out var actionType))
            return BadRequest(new { success = false, errors = new[] { $"Invalid action type: {dto.ActionType}" } });

        var playbook = new ResponsePlaybook
        {
            Name = dto.Name,
            Description = dto.Description,
            ActionType = actionType,
            ActionConfig = dto.ActionConfig,
            RequiresApproval = dto.RequiresApproval,
            IsActive = dto.IsActive,
            TriggerCondition = dto.TriggerCondition
        };

        _context.Set<ResponsePlaybook>().Add(playbook);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetById), new { id = playbook.Id },
            new { success = true, data = new { playbook.Id }, message = "Playbook created" });
    }

    /// <summary>
    /// Update a playbook.
    /// </summary>
    [HttpPut("{id:guid}")]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> Update(Guid id, [FromBody] PlaybookCreateDto dto)
    {
        var playbook = await _context.Set<ResponsePlaybook>().FindAsync(id);
        if (playbook == null)
            return NotFound(new { success = false, errors = new[] { "Playbook not found" } });

        if (Enum.TryParse<PlaybookActionType>(dto.ActionType, true, out var actionType))
            playbook.ActionType = actionType;

        playbook.Name = dto.Name;
        playbook.Description = dto.Description;
        playbook.ActionConfig = dto.ActionConfig;
        playbook.RequiresApproval = dto.RequiresApproval;
        playbook.IsActive = dto.IsActive;
        playbook.TriggerCondition = dto.TriggerCondition;

        await _context.SaveChangesAsync();
        return Ok(new { success = true, message = "Playbook updated" });
    }

    /// <summary>
    /// Toggle a playbook's active status.
    /// </summary>
    [HttpPatch("{id:guid}/toggle")]
    [Authorize(Policy = "SOCManager")]
    public async Task<IActionResult> Toggle(Guid id)
    {
        var playbook = await _context.Set<ResponsePlaybook>().FindAsync(id);
        if (playbook == null)
            return NotFound(new { success = false, errors = new[] { "Playbook not found" } });

        playbook.IsActive = !playbook.IsActive;
        await _context.SaveChangesAsync();

        return Ok(new { success = true, data = new { playbook.Id, playbook.IsActive } });
    }

    // ── Execution & Approval Workflow ──

    /// <summary>
    /// Manually trigger a playbook for a specific alert.
    /// </summary>
    [HttpPost("{id:guid}/trigger")]
    public async Task<IActionResult> ManualTrigger(Guid id, [FromBody] PlaybookTriggerDto dto)
    {
        var playbook = await _context.Set<ResponsePlaybook>().FindAsync(id);
        if (playbook == null)
            return NotFound(new { success = false, errors = new[] { "Playbook not found" } });

        var alert = await _context.Alerts.FindAsync(dto.AlertId);
        if (alert == null)
            return BadRequest(new { success = false, errors = new[] { "Alert not found" } });

        var execution = new PlaybookExecution
        {
            PlaybookId = id,
            AlertId = dto.AlertId,
            Status = playbook.RequiresApproval ? "Pending" : "Approved",
            ApprovedAt = playbook.RequiresApproval ? null : DateTime.UtcNow
        };

        _context.Set<PlaybookExecution>().Add(execution);
        await _context.SaveChangesAsync();

        return Ok(new
        {
            success = true,
            data = new { execution.Id, execution.Status },
            message = playbook.RequiresApproval
                ? "Execution pending analyst approval"
                : "Execution approved and queued"
        });
    }

    /// <summary>
    /// Get all pending executions awaiting approval.
    /// </summary>
    [HttpGet("executions/pending")]
    public async Task<IActionResult> GetPendingExecutions()
    {
        var pending = await _context.Set<PlaybookExecution>()
            .Include(e => e.Playbook)
            .Include(e => e.Alert)
            .Where(e => e.Status == "Pending")
            .OrderBy(e => e.CreatedAt)
            .Select(e => new
            {
                e.Id,
                PlaybookName = e.Playbook.Name,
                ActionType = e.Playbook.ActionType.ToString(),
                AlertTitle = e.Alert.Title,
                AlertSeverity = e.Alert.Severity.ToString(),
                AffectedUser = e.Alert.AffectedUser,
                SourceIP = e.Alert.SourceIP,
                e.CreatedAt
            })
            .ToListAsync();

        return Ok(new { success = true, data = pending });
    }

    /// <summary>
    /// Approve a pending playbook execution.
    /// </summary>
    [HttpPost("executions/{executionId:guid}/approve")]
    [Authorize(Policy = "SOCManager")]
    public async Task<IActionResult> Approve(Guid executionId)
    {
        var execution = await _context.Set<PlaybookExecution>().FindAsync(executionId);
        if (execution == null)
            return NotFound(new { success = false, errors = new[] { "Execution not found" } });

        if (execution.Status != "Pending")
            return BadRequest(new { success = false, errors = new[] { $"Cannot approve execution in '{execution.Status}' status" } });

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        Guid.TryParse(userId, out var approverGuid);

        execution.Status = "Approved";
        execution.ApprovedBy = approverGuid;
        execution.ApprovedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = "Execution approved — will be processed shortly" });
    }

    /// <summary>
    /// Reject a pending playbook execution.
    /// </summary>
    [HttpPost("executions/{executionId:guid}/reject")]
    [Authorize(Policy = "SOCManager")]
    public async Task<IActionResult> Reject(Guid executionId, [FromBody] PlaybookRejectDto? dto)
    {
        var execution = await _context.Set<PlaybookExecution>().FindAsync(executionId);
        if (execution == null)
            return NotFound(new { success = false, errors = new[] { "Execution not found" } });

        if (execution.Status != "Pending")
            return BadRequest(new { success = false, errors = new[] { $"Cannot reject execution in '{execution.Status}' status" } });

        execution.Status = "Rejected";
        execution.ErrorMessage = dto?.Reason ?? "Rejected by analyst";
        execution.CompletedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = "Execution rejected" });
    }

    /// <summary>
    /// Get execution history for all playbooks (audit trail).
    /// </summary>
    [HttpGet("executions/history")]
    public async Task<IActionResult> GetHistory([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        var query = _context.Set<PlaybookExecution>()
            .Include(e => e.Playbook)
            .Include(e => e.Alert)
            .OrderByDescending(e => e.CreatedAt);

        var total = await query.CountAsync();

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(e => new
            {
                e.Id,
                PlaybookName = e.Playbook.Name,
                ActionType = e.Playbook.ActionType.ToString(),
                AlertTitle = e.Alert.Title,
                e.Status,
                e.Result,
                e.ErrorMessage,
                e.CreatedAt,
                e.ApprovedAt,
                e.ExecutedAt,
                e.CompletedAt
            })
            .ToListAsync();

        return Ok(new { success = true, data = new { items, total, page, pageSize } });
    }
}

// ── DTOs ──

public class PlaybookCreateDto
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string ActionType { get; set; } = "BlockIp";
    public string? ActionConfig { get; set; }
    public bool RequiresApproval { get; set; } = true;
    public bool IsActive { get; set; } = true;
    public string? TriggerCondition { get; set; }
}

public class PlaybookTriggerDto
{
    public Guid AlertId { get; set; }
}

public class PlaybookRejectDto
{
    public string? Reason { get; set; }
}
