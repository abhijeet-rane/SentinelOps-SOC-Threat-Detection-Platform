namespace SOCPlatform.Core.Entities;

/// <summary>
/// Immutable, tamper-evident audit log entry.
/// Uses SHA-256 hash chain for integrity verification.
/// Append-only – entries are never updated or deleted.
/// </summary>
public class AuditLog
{
    public long Id { get; set; }
    public Guid? UserId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string Resource { get; set; } = string.Empty;
    public string? ResourceId { get; set; }
    public string? OldValue { get; set; }
    public string? NewValue { get; set; }
    public string? Details { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string EntryHash { get; set; } = string.Empty;         // SHA-256 of this entry
    public string? PreviousHash { get; set; }                     // SHA-256 of previous entry (chain)
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    // Navigation
    public User? User { get; set; }
}
