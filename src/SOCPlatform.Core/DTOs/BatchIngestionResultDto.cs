namespace SOCPlatform.Core.DTOs;

/// <summary>
/// Result of a batch log ingestion operation.
/// </summary>
public class BatchIngestionResultDto
{
    public int Accepted { get; set; }
    public int Failed { get; set; }
    public int Total { get; set; }
    public List<long> LogIds { get; set; } = new();
}
