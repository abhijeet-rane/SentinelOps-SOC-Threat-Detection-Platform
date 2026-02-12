namespace SOCPlatform.Core.Entities;

/// <summary>
/// Evidence attachments for incident investigations (logs, screenshots, file hashes).
/// </summary>
public class IncidentEvidence
{
    public Guid Id { get; set; }
    public Guid IncidentId { get; set; }
    public string FileName { get; set; } = string.Empty;
    public string FileType { get; set; } = string.Empty;
    public string? StoragePath { get; set; }
    public string? Hash { get; set; }
    public long FileSizeBytes { get; set; }
    public Guid UploadedBy { get; set; }
    public DateTime UploadedAt { get; set; } = DateTime.UtcNow;

    // Navigation
    public Incident Incident { get; set; } = null!;
}
