namespace SOCPlatform.Core.Entities;

/// <summary>
/// Detection rule configuration for the threat detection engine.
/// Rules can be toggled (enable/disable) by SOC Managers or CRUD-managed by System Admins.
/// </summary>
public class DetectionRule
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string RuleType { get; set; } = string.Empty;     // Threshold, Correlation, Anomaly
    public string? RuleLogic { get; set; }                    // JSONB – rule parameters
    public string Severity { get; set; } = string.Empty;
    public string? MitreTechnique { get; set; }
    public string? MitreTactic { get; set; }
    public bool IsActive { get; set; } = true;
    public int? ThresholdCount { get; set; }
    public int? TimeWindowSeconds { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
    public Guid? CreatedBy { get; set; }

    // Navigation
    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}
