namespace SOCPlatform.Core.Entities;

/// <summary>
/// Analyst notes attached to an incident for collaboration and investigation tracking.
/// </summary>
public class IncidentNote
{
    public Guid Id { get; set; }
    public Guid IncidentId { get; set; }
    public Guid AuthorId { get; set; }
    public string Content { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Navigation
    public Incident Incident { get; set; } = null!;
    public User Author { get; set; } = null!;
}
