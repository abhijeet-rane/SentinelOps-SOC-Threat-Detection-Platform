using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Service for ingesting, normalizing, and enriching log data from endpoint agents.
/// </summary>
public interface ILogIngestionService
{
    Task<long> IngestSingleAsync(LogIngestionDto dto);
    Task<BatchIngestionResultDto> IngestBatchAsync(BatchLogIngestionDto batchDto);
    Task EnrichLogAsync(Log log);
}
