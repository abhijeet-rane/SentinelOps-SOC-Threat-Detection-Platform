namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Audit logging service interface for tamper-evident audit trail.
/// </summary>
public interface IAuditService
{
    Task LogAsync(Guid? userId, string action, string resource, string? resourceId = null,
        string? oldValue = null, string? newValue = null, string? ipAddress = null, string? userAgent = null,
        string? details = null);
    Task<bool> VerifyChainIntegrityAsync();
}
