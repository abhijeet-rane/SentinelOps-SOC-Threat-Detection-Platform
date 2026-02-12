using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// Immutable audit logging service with SHA-256 hash chain for tamper detection.
/// Every entry is hashed with the previous entry's hash to form a verifiable chain.
/// </summary>
public class AuditService : IAuditService
{
    private readonly SOCDbContext _context;
    private readonly ILogger<AuditService> _logger;

    public AuditService(SOCDbContext context, ILogger<AuditService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task LogAsync(Guid? userId, string action, string resource, string? resourceId = null,
        string? oldValue = null, string? newValue = null, string? ipAddress = null, string? userAgent = null,
        string? details = null)
    {
        // Get the previous entry's hash for chain continuity
        var previousHash = await _context.AuditLogs
            .OrderByDescending(a => a.Id)
            .Select(a => a.EntryHash)
            .FirstOrDefaultAsync();

        var entry = new AuditLog
        {
            UserId = userId,
            Action = action,
            Resource = resource,
            ResourceId = resourceId,
            OldValue = oldValue,
            NewValue = newValue,
            Details = details,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            PreviousHash = previousHash,
            Timestamp = DateTime.UtcNow
        };

        // Compute SHA-256 hash of this entry (includes previousHash for chain)
        entry.EntryHash = ComputeEntryHash(entry);

        _context.AuditLogs.Add(entry);
        await _context.SaveChangesAsync();
    }

    public async Task<bool> VerifyChainIntegrityAsync()
    {
        var entries = await _context.AuditLogs
            .OrderBy(a => a.Id)
            .ToListAsync();

        if (entries.Count == 0) return true;

        string? previousHash = null;

        foreach (var entry in entries)
        {
            // Verify the previous hash pointer matches
            if (entry.PreviousHash != previousHash)
            {
                _logger.LogCritical("Audit chain broken at entry {Id}: expected PreviousHash={Expected}, got {Actual}",
                    entry.Id, previousHash, entry.PreviousHash);
                return false;
            }

            // Recompute and verify the entry hash
            var computedHash = ComputeEntryHash(entry);
            if (entry.EntryHash != computedHash)
            {
                _logger.LogCritical("Audit entry {Id} tampered: stored hash does not match computed hash", entry.Id);
                return false;
            }

            previousHash = entry.EntryHash;
        }

        _logger.LogInformation("Audit chain integrity verified: {Count} entries OK", entries.Count);
        return true;
    }

    private static string ComputeEntryHash(AuditLog entry)
    {
        var payload = JsonSerializer.Serialize(new
        {
            entry.UserId,
            entry.Action,
            entry.Resource,
            entry.ResourceId,
            entry.OldValue,
            entry.NewValue,
            entry.Details,
            entry.IpAddress,
            entry.UserAgent,
            entry.PreviousHash,
            Timestamp = entry.Timestamp.ToString("O")
        });

        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexStringLower(hashBytes);
    }
}
