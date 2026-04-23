namespace SOCPlatform.Core.Entities;

/// <summary>
/// Represents a user in the SOC platform with authentication and role assignment.
/// </summary>
public class User
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public Guid RoleId { get; set; }
    public bool IsActive { get; set; } = true;
    public bool IsLockedOut { get; set; } = false;
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }
    public DateTime? LastLogin { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiry { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    // ── Multi-Factor Authentication (TOTP, RFC 6238) ──
    //
    // MfaSecret stores the 160-bit TOTP shared secret AES-encrypted via
    // ASP.NET Core Data Protection. MfaBackupCodes is a JSONB array of
    // BCrypt-hashed one-time recovery codes. A user can have a pending
    // secret (MfaSecret set but MfaEnabled = false) between /mfa/setup
    // and /mfa/enable — once the first code is verified, MfaEnabled is
    // flipped and MfaEnabledAt is recorded.
    public byte[]? MfaSecret { get; set; }
    public bool MfaEnabled { get; set; } = false;
    public DateTime? MfaEnabledAt { get; set; }
    public List<string> MfaBackupCodes { get; set; } = new();
    public int MfaFailedAttempts { get; set; } = 0;

    // Navigation
    public Role Role { get; set; } = null!;
    public ICollection<Alert> AssignedAlerts { get; set; } = new List<Alert>();
    public ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
}
