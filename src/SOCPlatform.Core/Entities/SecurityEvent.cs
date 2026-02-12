namespace SOCPlatform.Core.Entities;

/// <summary>
/// Represents a security-relevant event derived from raw logs.
/// Enriched with MITRE ATT&CK mapping and threat intelligence context.
/// </summary>
public class SecurityEvent
{
    public long Id { get; set; }
    public long LogId { get; set; }
    public string EventCategory { get; set; } = string.Empty;
    public string EventAction { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string? MitreTechnique { get; set; }
    public string? MitreTactic { get; set; }
    public string? AffectedUser { get; set; }
    public string? AffectedDevice { get; set; }
    public string? SourceIP { get; set; }
    public string? DestinationIP { get; set; }
    public int? DestinationPort { get; set; }
    public string? FileHash { get; set; }
    public string? Metadata { get; set; }           // JSONB
    public bool IsThreatIntelMatch { get; set; } = false;
    public DateTime Timestamp { get; set; }

    // Navigation
    public Log Log { get; set; } = null!;
    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}
