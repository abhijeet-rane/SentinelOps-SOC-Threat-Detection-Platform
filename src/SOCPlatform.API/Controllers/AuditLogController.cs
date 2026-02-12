using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Audit log viewer: paginated, filterable, with hash-chain integrity verification.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AuditLogController : ControllerBase
{
    private readonly SOCDbContext _context;

    public AuditLogController(SOCDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Get audit logs with filtering by entity, action, user, and date range.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "ViewAuditLogs")]
    public async Task<IActionResult> GetAll(
        [FromQuery] string? entity,
        [FromQuery] string? action,
        [FromQuery] string? user,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25)
    {
        var query = _context.AuditLogs
            .Include(a => a.User)
            .AsNoTracking()
            .AsQueryable();

        if (!string.IsNullOrEmpty(entity))
            query = query.Where(a => a.Resource == entity);

        if (!string.IsNullOrEmpty(action))
            query = query.Where(a => a.Action.Contains(action));

        if (!string.IsNullOrEmpty(user))
            query = query.Where(a => a.User != null && a.User.Username.Contains(user));

        if (from.HasValue)
            query = query.Where(a => a.Timestamp >= from.Value);

        if (to.HasValue)
            query = query.Where(a => a.Timestamp <= to.Value);

        var totalCount = await query.CountAsync();

        var items = await query
            .OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new
            {
                a.Id,
                a.Action,
                User = a.User != null ? a.User.Username : "System",
                Entity = a.Resource,
                a.ResourceId,
                Detail = a.Details ?? $"{a.Action} on {a.Resource}",
                a.IpAddress,
                Timestamp = a.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                a.EntryHash,
            })
            .ToListAsync();

        return Ok(ApiResponse<object>.Ok(new
        {
            items,
            totalCount,
            page,
            pageSize,
            totalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        }));
    }

    /// <summary>
    /// Verify audit log hash chain integrity.
    /// </summary>
    [HttpGet("integrity")]
    [Authorize(Policy = "ViewAuditLogs")]
    public async Task<IActionResult> VerifyIntegrity()
    {
        var logs = await _context.AuditLogs
            .OrderBy(a => a.Id)
            .Select(a => new { a.Id, a.EntryHash, a.PreviousHash })
            .ToListAsync();

        var broken = new List<long>();
        for (int i = 1; i < logs.Count; i++)
        {
            if (logs[i].PreviousHash != logs[i - 1].EntryHash)
                broken.Add(logs[i].Id);
        }

        return Ok(ApiResponse<object>.Ok(new
        {
            totalEntries = logs.Count,
            integrityValid = broken.Count == 0,
            brokenLinks = broken.Count,
            brokenEntryIds = broken.Take(10)
        }));
    }
}
