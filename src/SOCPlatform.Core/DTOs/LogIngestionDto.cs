namespace SOCPlatform.Core.DTOs;

/// <summary>
/// Common event schema DTO for log ingestion from endpoint agents.
/// </summary>
public class LogIngestionDto
{
    public Guid EndpointId { get; set; }
    public string Source { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string Severity { get; set; } = "Low";
    public string? RawData { get; set; }
    public string? SourceIP { get; set; }
    public string? Hostname { get; set; }
    public string? Username { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// Batch log ingestion request.
/// </summary>
public class BatchLogIngestionDto
{
    public Guid EndpointId { get; set; }
    public string AgentVersion { get; set; } = string.Empty;
    public List<LogIngestionDto> Logs { get; set; } = new();
}
