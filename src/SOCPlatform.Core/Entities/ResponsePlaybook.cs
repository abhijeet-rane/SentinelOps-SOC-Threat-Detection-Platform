using SOCPlatform.Core.Enums;

namespace SOCPlatform.Core.Entities;

/// <summary>
/// SOAR response playbook definition with configurable actions and approval requirements.
/// </summary>
public class ResponsePlaybook
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public PlaybookActionType ActionType { get; set; }
    public string? ActionConfig { get; set; }          // JSONB
    public bool RequiresApproval { get; set; } = true;
    public bool IsActive { get; set; } = true;
    public string? TriggerCondition { get; set; }      // When to auto-trigger
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Navigation
    public ICollection<PlaybookExecution> Executions { get; set; } = new List<PlaybookExecution>();
}
