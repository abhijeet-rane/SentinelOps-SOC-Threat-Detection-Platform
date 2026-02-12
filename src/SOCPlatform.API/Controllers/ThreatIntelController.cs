using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Services;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Enterprise Threat Intelligence Controller.
/// Manages IOC lifecycle, enrichment lookups, bulk feed import, and statistics.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ThreatIntelController : ControllerBase
{
    private readonly ThreatIntelService _service;
    private readonly SOCDbContext _db;

    public ThreatIntelController(ThreatIntelService service, SOCDbContext db)
    {
        _service = service;
        _db = db;
    }

    // ──────────────── List / Search ────────────────

    /// <summary>
    /// List indicators with filtering, searching, sorting, and pagination.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetIndicators([FromQuery] ThreatIntelFilterDto filter)
    {
        var query = _db.ThreatIntelIndicators.AsQueryable();

        // Filters
        if (!string.IsNullOrEmpty(filter.IndicatorType) && Enum.TryParse<IndicatorType>(filter.IndicatorType, true, out var iType))
            query = query.Where(i => i.IndicatorType == iType);
        if (!string.IsNullOrEmpty(filter.ThreatLevel))
            query = query.Where(i => i.ThreatLevel == filter.ThreatLevel);
        if (!string.IsNullOrEmpty(filter.ThreatType))
            query = query.Where(i => i.ThreatType.Contains(filter.ThreatType));
        if (!string.IsNullOrEmpty(filter.Source))
            query = query.Where(i => i.Source.Contains(filter.Source));
        if (!string.IsNullOrEmpty(filter.SearchValue))
            query = query.Where(i => i.Value.Contains(filter.SearchValue) || (i.Description != null && i.Description.Contains(filter.SearchValue)));
        if (!string.IsNullOrEmpty(filter.Tag))
            query = query.Where(i => i.Tags != null && i.Tags.Contains(filter.Tag));
        if (filter.IsActive.HasValue)
            query = query.Where(i => i.IsActive == filter.IsActive.Value);
        if (filter.HasMatches.HasValue)
            query = filter.HasMatches.Value ? query.Where(i => i.HitCount > 0) : query.Where(i => i.HitCount == 0);

        var total = await query.CountAsync();

        // Sorting
        query = filter.SortBy?.ToLower() switch
        {
            "value" => filter.SortOrder == "asc" ? query.OrderBy(i => i.Value) : query.OrderByDescending(i => i.Value),
            "threatlevel" => filter.SortOrder == "asc" ? query.OrderBy(i => i.ThreatLevel) : query.OrderByDescending(i => i.ThreatLevel),
            "hitcount" => filter.SortOrder == "asc" ? query.OrderBy(i => i.HitCount) : query.OrderByDescending(i => i.HitCount),
            "confidencescore" => filter.SortOrder == "asc" ? query.OrderBy(i => i.ConfidenceScore) : query.OrderByDescending(i => i.ConfidenceScore),
            "lastmatchedat" => filter.SortOrder == "asc" ? query.OrderBy(i => i.LastMatchedAt) : query.OrderByDescending(i => i.LastMatchedAt),
            _ => filter.SortOrder == "asc" ? query.OrderBy(i => i.CreatedAt) : query.OrderByDescending(i => i.CreatedAt),
        };

        var items = await query
            .Skip((filter.Page - 1) * filter.PageSize)
            .Take(filter.PageSize)
            .Select(i => new ThreatIntelDto
            {
                Id = i.Id,
                IndicatorType = i.IndicatorType.ToString(),
                Value = i.Value,
                Source = i.Source,
                ConfidenceScore = i.ConfidenceScore,
                ThreatType = i.ThreatType,
                ThreatLevel = i.ThreatLevel,
                Description = i.Description,
                Tags = i.Tags,
                AssociatedCVEs = i.AssociatedCVEs,
                MitreTechniques = i.MitreTechniques,
                GeoCountry = i.GeoCountry,
                ASN = i.ASN,
                HitCount = i.HitCount,
                LastMatchedAt = i.LastMatchedAt,
                IsActive = i.IsActive,
                FirstSeenAt = i.FirstSeenAt,
                CreatedAt = i.CreatedAt,
                ExpiresAt = i.ExpiresAt,
            }).ToListAsync();

        return Ok(new
        {
            success = true,
            data = new { items, total, page = filter.Page, pageSize = filter.PageSize, totalPages = (int)Math.Ceiling(total / (double)filter.PageSize) }
        });
    }

    /// <summary>Get a single indicator by ID.</summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetIndicator(Guid id)
    {
        var indicator = await _db.ThreatIntelIndicators.FindAsync(id);
        if (indicator == null) return NotFound(new { success = false, message = "Indicator not found" });

        return Ok(new
        {
            success = true,
            data = new ThreatIntelDto
            {
                Id = indicator.Id,
                IndicatorType = indicator.IndicatorType.ToString(),
                Value = indicator.Value,
                Source = indicator.Source,
                ConfidenceScore = indicator.ConfidenceScore,
                ThreatType = indicator.ThreatType,
                ThreatLevel = indicator.ThreatLevel,
                Description = indicator.Description,
                Tags = indicator.Tags,
                AssociatedCVEs = indicator.AssociatedCVEs,
                MitreTechniques = indicator.MitreTechniques,
                GeoCountry = indicator.GeoCountry,
                ASN = indicator.ASN,
                HitCount = indicator.HitCount,
                LastMatchedAt = indicator.LastMatchedAt,
                IsActive = indicator.IsActive,
                FirstSeenAt = indicator.FirstSeenAt,
                CreatedAt = indicator.CreatedAt,
                ExpiresAt = indicator.ExpiresAt,
            }
        });
    }

    // ──────────────── Create / Import ────────────────

    /// <summary>Create a single indicator.</summary>
    [HttpPost]
    public async Task<IActionResult> CreateIndicator([FromBody] CreateThreatIntelDto dto)
    {
        try
        {
            var indicator = await _service.CreateAsync(dto);
            return Ok(new { success = true, message = "Indicator created", data = new { indicator.Id } });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { success = false, message = ex.Message });
        }
    }

    /// <summary>Bulk import indicators from a feed.</summary>
    [HttpPost("import")]
    public async Task<IActionResult> BulkImport([FromBody] BulkImportDto dto)
    {
        var result = await _service.BulkImportAsync(dto);
        return Ok(new
        {
            success = true,
            message = $"Imported {result.Imported} indicators from {result.FeedName}",
            data = result
        });
    }

    /// <summary>Seed demo threat intel data.</summary>
    [HttpPost("seed")]
    public async Task<IActionResult> SeedDemoData()
    {
        await _service.SeedDemoDataAsync();
        return Ok(new { success = true, message = "Demo threat intel data seeded" });
    }

    // ──────────────── Update / Delete ────────────────

    /// <summary>Update an existing indicator.</summary>
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> UpdateIndicator(Guid id, [FromBody] CreateThreatIntelDto dto)
    {
        var indicator = await _db.ThreatIntelIndicators.FindAsync(id);
        if (indicator == null) return NotFound(new { success = false, message = "Indicator not found" });

        if (Enum.TryParse<IndicatorType>(dto.IndicatorType, true, out var type))
            indicator.IndicatorType = type;

        indicator.Value = dto.Value.Trim().ToLowerInvariant();
        indicator.Source = dto.Source;
        indicator.ConfidenceScore = Math.Clamp(dto.ConfidenceScore, 0, 100);
        indicator.ThreatType = dto.ThreatType;
        indicator.ThreatLevel = dto.ThreatLevel;
        indicator.Description = dto.Description;
        indicator.Tags = dto.Tags;
        indicator.AssociatedCVEs = dto.AssociatedCVEs;
        indicator.MitreTechniques = dto.MitreTechniques;
        indicator.GeoCountry = dto.GeoCountry;
        indicator.ASN = dto.ASN;
        indicator.ExpiresAt = dto.ExpiresAt;
        indicator.UpdatedAt = DateTime.UtcNow;

        await _db.SaveChangesAsync();
        return Ok(new { success = true, message = "Indicator updated" });
    }

    /// <summary>Toggle indicator active status.</summary>
    [HttpPatch("{id:guid}/toggle")]
    public async Task<IActionResult> ToggleIndicator(Guid id)
    {
        var indicator = await _db.ThreatIntelIndicators.FindAsync(id);
        if (indicator == null) return NotFound(new { success = false, message = "Indicator not found" });

        indicator.IsActive = !indicator.IsActive;
        indicator.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        return Ok(new { success = true, message = $"Indicator {(indicator.IsActive ? "activated" : "deactivated")}", data = new { indicator.IsActive } });
    }

    /// <summary>Delete an indicator.</summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> DeleteIndicator(Guid id)
    {
        var indicator = await _db.ThreatIntelIndicators.FindAsync(id);
        if (indicator == null) return NotFound(new { success = false, message = "Indicator not found" });

        _db.ThreatIntelIndicators.Remove(indicator);
        await _db.SaveChangesAsync();
        return Ok(new { success = true, message = "Indicator deleted" });
    }

    // ──────────────── Enrichment ────────────────

    /// <summary>
    /// Enrich a single value (IP, domain, hash, URL, email) against all active indicators.
    /// </summary>
    [HttpPost("enrich")]
    public async Task<IActionResult> Enrich([FromBody] EnrichmentRequest request)
    {
        var result = await _service.EnrichAsync(request.Value, request.Type);
        return Ok(new { success = true, data = result });
    }

    /// <summary>
    /// Enrich multiple fields from a log entry (source IP, dest IP, hash, domain).
    /// </summary>
    [HttpPost("enrich/log")]
    public async Task<IActionResult> EnrichLog([FromBody] LogEnrichmentRequest request)
    {
        var results = await _service.EnrichLogFieldsAsync(
            request.SourceIp, request.DestinationIp, request.FileHash, request.Domain);
        return Ok(new
        {
            success = true,
            data = new
            {
                totalMatches = results.Sum(r => r.MatchCount),
                isMalicious = results.Any(r => r.IsMalicious),
                results = results,
            }
        });
    }

    /// <summary>
    /// Auto-escalate an alert's severity based on threat intel matches.
    /// </summary>
    [HttpPost("escalate/{alertId:guid}")]
    public async Task<IActionResult> AutoEscalate(Guid alertId)
    {
        var escalated = await _service.AutoEscalateAlertAsync(alertId);
        return Ok(new { success = true, escalated, message = escalated ? "Alert severity escalated based on threat intel" : "No escalation needed" });
    }

    // ──────────────── Statistics ────────────────

    /// <summary>Dashboard stats for threat intel overview.</summary>
    [HttpGet("stats")]
    public async Task<IActionResult> GetStats()
    {
        var stats = await _service.GetStatsAsync();
        return Ok(new { success = true, data = stats });
    }
}

public class EnrichmentRequest
{
    public string Value { get; set; } = string.Empty;
    public string? Type { get; set; }
}

public class LogEnrichmentRequest
{
    public string? SourceIp { get; set; }
    public string? DestinationIp { get; set; }
    public string? FileHash { get; set; }
    public string? Domain { get; set; }
}
