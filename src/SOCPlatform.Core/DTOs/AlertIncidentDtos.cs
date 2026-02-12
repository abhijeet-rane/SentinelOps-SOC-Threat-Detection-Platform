using SOCPlatform.Core.Enums;

namespace SOCPlatform.Core.DTOs;

public class AlertDto
{
    public Guid Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? DetectionRuleName { get; set; }
    public string? MitreTechnique { get; set; }
    public string? MitreTactic { get; set; }
    public string? AffectedUser { get; set; }
    public string? AffectedDevice { get; set; }
    public string? SourceIP { get; set; }
    public string? RecommendedAction { get; set; }
    public string? AssignedAnalystName { get; set; }
    public Guid? AssignedTo { get; set; }
    public Guid? IncidentId { get; set; }
    public Guid? DetectionRuleId { get; set; }
    public long? EventId { get; set; }
    public DateTime? SlaDeadline { get; set; }
    public bool IsSlaBreach => SlaDeadline.HasValue && DateTime.UtcNow > SlaDeadline.Value
        && Status != "Resolved" && Status != "Closed";
    public DateTime? AcknowledgedAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public DateTime? ClosedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public class AlertStatusUpdateDto
{
    public AlertStatus NewStatus { get; set; }
    public string? Notes { get; set; }
}

public class AlertAssignDto
{
    public Guid AnalystId { get; set; }
}

public class AlertFilterDto
{
    public Severity? Severity { get; set; }
    public AlertStatus? Status { get; set; }
    public string? DetectionRuleName { get; set; }
    public string? AffectedUser { get; set; }
    public string? SourceIP { get; set; }
    public Guid? AssignedTo { get; set; }
    public bool? SlaBreach { get; set; }
    public DateTime? From { get; set; }
    public DateTime? To { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 20;
    public string SortBy { get; set; } = "CreatedAt";
    public bool SortDesc { get; set; } = true;
}

public class PagedResultDto<T>
{
    public List<T> Items { get; set; } = new();
    public int TotalCount { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
    public int TotalPages => (int)Math.Ceiling(TotalCount / (double)PageSize);
}

// ── Incident DTOs ──

public class IncidentDto
{
    public Guid Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? RootCause { get; set; }
    public string? ImpactAssessment { get; set; }
    public string? AssignedAnalystName { get; set; }
    public Guid? AssignedAnalystId { get; set; }
    public int AlertCount { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public DateTime? ClosedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public List<AlertDto> Alerts { get; set; } = new();
    public List<IncidentNoteDto> Notes { get; set; } = new();
    public List<IncidentEvidenceDto> Evidence { get; set; } = new();
    public List<TimelineEntryDto> Timeline { get; set; } = new();
}

public class CreateIncidentDto
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = "Medium";
    public List<Guid> AlertIds { get; set; } = new();
}

public class UpdateIncidentDto
{
    public string? Title { get; set; }
    public string? Description { get; set; }
    public Severity? Severity { get; set; }
    public IncidentStatus? Status { get; set; }
    public string? RootCause { get; set; }
    public string? ImpactAssessment { get; set; }
    public Guid? AssignedAnalystId { get; set; }
}

public class IncidentNoteDto
{
    public Guid Id { get; set; }
    public Guid AuthorId { get; set; }
    public string Content { get; set; } = string.Empty;
    public string AuthorName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public class AddIncidentNoteDto
{
    public string Content { get; set; } = string.Empty;
}

public class IncidentEvidenceDto
{
    public Guid Id { get; set; }
    public string FileName { get; set; } = string.Empty;
    public string FileType { get; set; } = string.Empty;
    public string? Hash { get; set; }
    public long FileSizeBytes { get; set; }
    public Guid UploadedBy { get; set; }
    public DateTime UploadedAt { get; set; }
}

public class TimelineEntryDto
{
    public DateTime Timestamp { get; set; }
    public string Type { get; set; } = string.Empty;    // Alert, Note, StatusChange, Evidence
    public string Description { get; set; } = string.Empty;
    public string? Actor { get; set; }
}

