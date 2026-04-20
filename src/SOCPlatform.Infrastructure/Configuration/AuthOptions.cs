using System.ComponentModel.DataAnnotations;

namespace SOCPlatform.Infrastructure.Configuration;

public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>Lifetime of password-reset tokens. Defaults to 1 hour.</summary>
    [Range(5, 1440)] public int PasswordResetTokenLifetimeMinutes { get; init; } = 60;

    /// <summary>Frontend base URL used to build reset links emailed to users.</summary>
    [Required, Url] public string FrontendBaseUrl { get; init; } = "http://localhost:5173";
}
