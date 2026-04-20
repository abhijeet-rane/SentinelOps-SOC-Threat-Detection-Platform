using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Interfaces;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Secure log ingestion endpoints for endpoint agents.
/// Authenticated via API key (X-API-Key header) with optional HMAC request signing.
/// </summary>
[ApiController]
[Asp.Versioning.ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/logs")]
[AllowAnonymous] // API key auth is handled by middleware, not JWT
public class LogIngestionController : ControllerBase
{
    private readonly ILogIngestionService _ingestionService;
    private readonly ILogger<LogIngestionController> _logger;

    public LogIngestionController(ILogIngestionService ingestionService, ILogger<LogIngestionController> logger)
    {
        _ingestionService = ingestionService;
        _logger = logger;
    }

    /// <summary>
    /// Ingest a batch of log entries from an endpoint agent.
    /// Rate limited to 1000 req/min per API key.
    /// </summary>
    [HttpPost("ingest")]
    [EnableRateLimiting("ingestion")]
    public async Task<IActionResult> IngestBatch([FromBody] BatchLogIngestionDto request)
    {
        var apiKeyId = HttpContext.Items["ApiKeyId"] as Guid?;
        _logger.LogInformation("Batch ingestion from API key {ApiKeyId}: {Count} logs",
            apiKeyId, request.Logs.Count);

        var result = await _ingestionService.IngestBatchAsync(request);

        return Ok(ApiResponse<BatchIngestionResultDto>.Ok(result,
            $"Accepted {result.Accepted}/{result.Total} logs"));
    }

    /// <summary>
    /// Ingest a single log entry from an endpoint agent.
    /// Rate limited to 1000 req/min per API key.
    /// </summary>
    [HttpPost("ingest/single")]
    [EnableRateLimiting("ingestion")]
    public async Task<IActionResult> IngestSingle([FromBody] LogIngestionDto request)
    {
        var logId = await _ingestionService.IngestSingleAsync(request);

        return CreatedAtAction(nameof(IngestSingle), new { id = logId },
            ApiResponse<object>.Ok(new { logId }, "Log ingested successfully"));
    }

    /// <summary>
    /// Health check for agent connectivity.
    /// </summary>
    [HttpGet("health")]
    public IActionResult Health()
    {
        return Ok(ApiResponse<object>.Ok(new
        {
            status = "healthy",
            timestamp = DateTime.UtcNow
        }));
    }
}
