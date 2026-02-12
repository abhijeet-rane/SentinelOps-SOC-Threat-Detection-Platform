namespace SOCPlatform.Core.Entities;

/// <summary>
/// Tracks execution of a SOAR playbook action against an alert.
/// Includes approval tracking and execution results.
/// </summary>
public class PlaybookExecution
{
    public Guid Id { get; set; }
    public Guid PlaybookId { get; set; }
    public Guid AlertId { get; set; }
    public string Status { get; set; } = "Pending";     // Pending, Approved, Executing, Completed, Failed, Rejected
    public Guid? ApprovedBy { get; set; }
    public Guid? ExecutedBy { get; set; }
    public string? Result { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ApprovedAt { get; set; }
    public DateTime? ExecutedAt { get; set; }
    public DateTime? CompletedAt { get; set; }

    // Navigation
    public ResponsePlaybook Playbook { get; set; } = null!;
    public Alert Alert { get; set; } = null!;
}
