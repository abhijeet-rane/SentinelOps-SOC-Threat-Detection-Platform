namespace SOCPlatform.Core.Entities;

/// <summary>
/// One-time password reset token. The plaintext token is sent via email; only its
/// SHA-256 hash is persisted, so a leaked DB row cannot be used to reset a password.
/// Tokens are single-use (UsedAt set on first successful redemption) and time-limited.
/// </summary>
public class PasswordResetToken
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }

    /// <summary>SHA-256 hex of the plaintext token (lowercase, 64 chars).</summary>
    public string TokenHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime? UsedAt { get; set; }

    /// <summary>IP that initiated the request (for audit / abuse detection).</summary>
    public string? RequestIpAddress { get; set; }
    public string? RequestUserAgent { get; set; }

    public User User { get; set; } = null!;
}
