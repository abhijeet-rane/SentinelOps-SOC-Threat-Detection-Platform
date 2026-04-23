using SOCPlatform.Core.DTOs;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// TOTP-based Multi-Factor Authentication (RFC 6238 / Google Authenticator).
///
/// Secrets are stored AES-encrypted at rest via ASP.NET Core Data Protection.
/// Backup codes are BCrypt-hashed so a DB leak alone cannot authenticate.
/// Tiered policy: optional for analysts, enforced at login for privileged roles.
/// </summary>
public interface IMfaService
{
    /// <summary>
    /// Generate a new pending TOTP secret for the user and return the otpauth URI
    /// + QR PNG. Does NOT enable MFA — caller must verify a code via EnableAsync.
    /// Overwrites any previously-pending secret if MFA is not yet enabled.
    /// </summary>
    Task<MfaSetupResponseDto> GenerateSetupAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Verify a TOTP code against the pending secret. On success, flips
    /// MfaEnabled = true, stamps MfaEnabledAt, generates 10 single-use backup
    /// codes (BCrypt-hashed), and returns them to the caller (shown once).
    /// </summary>
    Task<MfaEnableResponseDto> EnableAsync(Guid userId, string code, CancellationToken ct = default);

    /// <summary>
    /// Disable MFA after verifying the user's current password + a valid TOTP
    /// code. Clears the secret and all backup codes.
    /// </summary>
    Task DisableAsync(Guid userId, string currentPassword, string totpCode, CancellationToken ct = default);

    /// <summary>
    /// Verify a TOTP code for an MFA-enabled user. Returns true on match within
    /// the ±1 × 30 s window. Increments MfaFailedAttempts on mismatch.
    /// </summary>
    Task<bool> VerifyCodeAsync(Guid userId, string code, CancellationToken ct = default);

    /// <summary>
    /// Verify and consume a backup code. If matched, the code is removed from
    /// MfaBackupCodes (single-use).
    /// </summary>
    Task<bool> ConsumeBackupCodeAsync(Guid userId, string backupCode, CancellationToken ct = default);

    /// <summary>Read current status without mutating anything.</summary>
    Task<MfaStatusDto> GetStatusAsync(Guid userId, CancellationToken ct = default);
}
