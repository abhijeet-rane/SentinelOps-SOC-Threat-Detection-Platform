using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.Entities;
using SOCPlatform.Detection.Rules;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// API for managing detection rules: CRUD, enable/disable, and listing with MITRE ATT&CK mapping.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class DetectionRulesController : ControllerBase
{
    private readonly SOCDbContext _context;
    private readonly IEnumerable<IDetectionRule> _activeRules;

    public DetectionRulesController(SOCDbContext context, IEnumerable<IDetectionRule> activeRules)
    {
        _context = context;
        _activeRules = activeRules;
    }

    /// <summary>
    /// Get all detection rules (DB-persisted configuration + in-memory active rules).
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var dbRules = await _context.DetectionRules.OrderBy(r => r.Name).ToListAsync();

        // Merge DB rules with in-memory rule status
        var result = dbRules.Select(r =>
        {
            var active = _activeRules.FirstOrDefault(ar => ar.Name == r.Name);
            return new
            {
                r.Id,
                r.Name,
                r.Description,
                r.RuleType,
                r.Severity,
                r.MitreTechnique,
                r.MitreTactic,
                r.IsActive,
                r.ThresholdCount,
                r.TimeWindowSeconds,
                RuntimeEnabled = active?.IsEnabled ?? false,
                r.CreatedAt,
                r.UpdatedAt
            };
        });

        return Ok(new { success = true, data = result });
    }

    /// <summary>
    /// Get a specific rule by ID.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var rule = await _context.DetectionRules.FindAsync(id);
        if (rule == null) return NotFound(new { success = false, errors = new[] { "Rule not found" } });
        return Ok(new { success = true, data = rule });
    }

    /// <summary>
    /// Create a new detection rule.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> Create([FromBody] DetectionRuleDto dto)
    {
        var rule = new DetectionRule
        {
            Name = dto.Name,
            Description = dto.Description,
            RuleType = dto.RuleType,
            Severity = dto.Severity,
            MitreTechnique = dto.MitreTechnique,
            MitreTactic = dto.MitreTactic,
            IsActive = dto.IsActive,
            ThresholdCount = dto.ThresholdCount,
            TimeWindowSeconds = dto.TimeWindowSeconds,
            RuleLogic = dto.RuleLogic
        };

        _context.DetectionRules.Add(rule);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetById), new { id = rule.Id }, new { success = true, data = rule });
    }

    /// <summary>
    /// Update a detection rule.
    /// </summary>
    [HttpPut("{id:guid}")]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> Update(Guid id, [FromBody] DetectionRuleDto dto)
    {
        var rule = await _context.DetectionRules.FindAsync(id);
        if (rule == null) return NotFound(new { success = false, errors = new[] { "Rule not found" } });

        rule.Name = dto.Name;
        rule.Description = dto.Description;
        rule.RuleType = dto.RuleType;
        rule.Severity = dto.Severity;
        rule.MitreTechnique = dto.MitreTechnique;
        rule.MitreTactic = dto.MitreTactic;
        rule.IsActive = dto.IsActive;
        rule.ThresholdCount = dto.ThresholdCount;
        rule.TimeWindowSeconds = dto.TimeWindowSeconds;
        rule.RuleLogic = dto.RuleLogic;
        rule.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();
        return Ok(new { success = true, data = rule });
    }

    /// <summary>
    /// Toggle a rule's active status (enable/disable).
    /// </summary>
    [HttpPatch("{id:guid}/toggle")]
    [Authorize(Policy = "SOCManager")]
    public async Task<IActionResult> Toggle(Guid id)
    {
        var rule = await _context.DetectionRules.FindAsync(id);
        if (rule == null) return NotFound(new { success = false, errors = new[] { "Rule not found" } });

        rule.IsActive = !rule.IsActive;
        rule.UpdatedAt = DateTime.UtcNow;

        // Also toggle the in-memory rule
        var activeRule = _activeRules.FirstOrDefault(r => r.Name == rule.Name);
        if (activeRule != null) activeRule.IsEnabled = rule.IsActive;

        await _context.SaveChangesAsync();

        return Ok(new { success = true, data = new { rule.Id, rule.Name, rule.IsActive } });
    }

    /// <summary>
    /// Delete a detection rule.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var rule = await _context.DetectionRules.FindAsync(id);
        if (rule == null) return NotFound(new { success = false, errors = new[] { "Rule not found" } });

        _context.DetectionRules.Remove(rule);
        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = $"Rule '{rule.Name}' deleted" });
    }
}

/// <summary>
/// DTO for creating/updating detection rules.
/// </summary>
public class DetectionRuleDto
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string RuleType { get; set; } = "Threshold";
    public string Severity { get; set; } = "Medium";
    public string? MitreTechnique { get; set; }
    public string? MitreTactic { get; set; }
    public bool IsActive { get; set; } = true;
    public int? ThresholdCount { get; set; }
    public int? TimeWindowSeconds { get; set; }
    public string? RuleLogic { get; set; }
}
