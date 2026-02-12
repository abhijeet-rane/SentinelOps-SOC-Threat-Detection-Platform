namespace SOCPlatform.Core.Entities;

/// <summary>
/// Represents a raw log ingested from an endpoint agent.
/// Uses a common event schema with JSONB for raw and normalized data.
/// </summary>
public class Log
{
    public long Id { get; set; }
    public Guid EndpointId { get; set; }
    public string Source { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string? RawData { get; set; }           // JSONB
    public string? NormalizedData { get; set; }     // JSONB
    public string? SourceIP { get; set; }
    public string? Hostname { get; set; }
    public string? Username { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime IngestedAt { get; set; } = DateTime.UtcNow;

    // Navigation
    public ICollection<SecurityEvent> Events { get; set; } = new List<SecurityEvent>();
}
