using System.ComponentModel.DataAnnotations;

namespace SOCPlatform.Infrastructure.Configuration;

public sealed class MlServiceOptions
{
    public const string SectionName = "MlService";

    [Required, Url] public string BaseUrl { get; init; } = "http://localhost:8001";
    [Range(1, 300)] public int TimeoutSeconds { get; init; } = 30;

    /// <summary>
    /// Shared secret sent to the Python ML service as the <c>X-API-Key</c>
    /// header. Must match the ML service's <c>ML_SERVICE_API_KEY</c> env var.
    /// Required in Production (startup validation enforces this).
    /// </summary>
    public string ApiKey { get; init; } = "";
}
