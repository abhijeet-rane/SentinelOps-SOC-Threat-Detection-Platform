using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Infrastructure.Services;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Proxy controller for the Python ML microservice.
/// Provides analyze, train, and status endpoints.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class MlController : ControllerBase
{
    private readonly MlIntegrationService _ml;

    public MlController(MlIntegrationService ml)
    {
        _ml = ml;
    }

    /// <summary>Health check – is the ML service running and which models are trained?</summary>
    [HttpGet("status")]
    public async Task<IActionResult> GetStatus()
    {
        var result = await _ml.GetStatusAsync();
        if (result == null)
            return Ok(ApiResponse<object>.Ok(new
            {
                status = "offline",
                message = "ML service is not reachable. Make sure the Python service is running on port 8001."
            }));
        return Ok(ApiResponse<MlStatusResult>.Ok(result));
    }

    /// <summary>Analyze an event for anomalies.</summary>
    [HttpPost("analyze")]
    public async Task<IActionResult> Analyze([FromBody] MlAnalyzeRequest request)
    {
        var result = await _ml.AnalyzeEventAsync(request);
        if (result == null)
            return StatusCode(503, ApiResponse<object>.Fail("ML service unavailable"));
        return Ok(ApiResponse<MlAnalyzeResult>.Ok(result));
    }

    /// <summary>Trigger model training / retraining.</summary>
    [HttpPost("train")]
    [Authorize(Roles = "Admin,SOC Manager")]
    public async Task<IActionResult> Train([FromBody] MlTrainRequest? request)
    {
        var model = request?.Model ?? "all";
        var result = await _ml.TriggerTrainingAsync(model);
        if (result == null)
            return StatusCode(503, ApiResponse<object>.Fail("ML service unavailable"));
        return Ok(ApiResponse<MlTrainResult>.Ok(result));
    }
}

/// <summary>DTO for the train request.</summary>
public class MlTrainRequest
{
    public string Model { get; set; } = "all";
}
