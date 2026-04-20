using System.ComponentModel.DataAnnotations;

namespace SOCPlatform.Infrastructure.Configuration;

public sealed class JwtOptions
{
    public const string SectionName = "JwtSettings";

    [Required, MinLength(32, ErrorMessage = "JWT secret must be at least 32 characters (256 bits).")]
    public string SecretKey { get; init; } = string.Empty;

    [Required] public string Issuer { get; init; } = string.Empty;
    [Required] public string Audience { get; init; } = string.Empty;

    [Range(1, 1440)] public int AccessTokenExpirationMinutes { get; init; } = 15;
    [Range(1, 90)]   public int RefreshTokenExpirationDays { get; init; } = 7;
}
