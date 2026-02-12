using SOCPlatform.Core.Enums;

namespace SOCPlatform.Core.Entities;

/// <summary>
/// Represents a security incident, correlating multiple alerts into a single investigation case.
/// </summary>
public class Incident
{
    public Guid Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public IncidentStatus Status { get; set; } = IncidentStatus.Open;
    public string? RootCause { get; set; }
    public string? ImpactAssessment { get; set; }
    public Guid? AssignedAnalystId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ResolvedAt { get; set; }
    public DateTime? ClosedAt { get; set; }
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // Navigation
    public User? AssignedAnalyst { get; set; }
    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
    public ICollection<IncidentNote> Notes { get; set; } = new List<IncidentNote>();
    public ICollection<IncidentEvidence> Evidence { get; set; } = new List<IncidentEvidence>();
}
