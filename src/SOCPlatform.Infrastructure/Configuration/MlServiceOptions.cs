using System.ComponentModel.DataAnnotations;

namespace SOCPlatform.Infrastructure.Configuration;

public sealed class MlServiceOptions
{
    public const string SectionName = "MlService";

    [Required, Url] public string BaseUrl { get; init; } = "http://localhost:8001";
    [Range(1, 300)] public int TimeoutSeconds { get; init; } = 30;
}
