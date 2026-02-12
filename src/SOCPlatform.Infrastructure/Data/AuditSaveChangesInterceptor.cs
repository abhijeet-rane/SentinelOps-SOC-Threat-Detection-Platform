using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SOCPlatform.Core.Entities;
using System.Text.Json;

namespace SOCPlatform.Infrastructure.Data;

/// <summary>
/// EF Core SaveChanges interceptor for automatic audit logging.
/// Captures all entity changes (insert/update/delete) and writes them to AuditLogs
/// with full old-value / new-value tracking.
/// </summary>
public class AuditSaveChangesInterceptor : SaveChangesInterceptor
{
    /// <summary>
    /// Captures entity changes after SaveChanges completes (to get DB-generated IDs).
    /// </summary>
    public override async ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData,
        int result,
        CancellationToken cancellationToken = default)
    {
        if (eventData.Context is SOCDbContext db)
        {
            await WriteAuditEntriesAsync(db);
        }

        return result;
    }

    private static async Task WriteAuditEntriesAsync(SOCDbContext db)
    {
        var pendingAudits = db.ChangeTracker.Entries()
            .Where(e => e.State is EntityState.Modified)
            .Where(e => e.Entity is not AuditLog) // Don't audit audit logs
            .ToList();

        if (pendingAudits.Count == 0) return;

        foreach (var entry in pendingAudits)
        {
            var entityType = entry.Entity.GetType().Name;
            var primaryKey = entry.Properties
                .FirstOrDefault(p => p.Metadata.IsPrimaryKey())?.CurrentValue?.ToString();

            var oldValues = new Dictionary<string, object?>();
            var newValues = new Dictionary<string, object?>();

            foreach (var prop in entry.Properties.Where(p => p.IsModified))
            {
                oldValues[prop.Metadata.Name] = prop.OriginalValue;
                newValues[prop.Metadata.Name] = prop.CurrentValue;
            }

            if (oldValues.Count == 0) continue;

            var auditEntry = new AuditLog
            {
                Action = "Update",
                Resource = entityType,
                ResourceId = primaryKey,
                OldValue = JsonSerializer.Serialize(oldValues),
                NewValue = JsonSerializer.Serialize(newValues),
                Timestamp = DateTime.UtcNow
            };

            db.AuditLogs.Add(auditEntry);
        }

        // Save audit entries without re-triggering this interceptor
        await db.SaveChangesAsync(acceptAllChangesOnSuccess: true);
    }
}
