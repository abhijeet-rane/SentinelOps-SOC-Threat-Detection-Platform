using SOCPlatform.Core.DTOs;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Log ingestion and storage service interface.
/// </summary>
public interface ILogService
{
    Task<long> IngestLogAsync(LogIngestionDto log);
    Task<int> IngestBatchAsync(BatchLogIngestionDto batch);
    Task<PagedResult<LogIngestionDto>> GetLogsAsync(int page, int pageSize, string? source = null, string? severity = null);
}
