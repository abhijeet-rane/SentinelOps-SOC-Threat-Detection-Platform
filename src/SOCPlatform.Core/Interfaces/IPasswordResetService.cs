using SOCPlatform.Core.DTOs;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Self-service password reset flow. Two stages:
///   1. RequestResetAsync — issue a token + send the email
///   2. ResetPasswordAsync — verify token + set new password + revoke all refresh tokens
/// Both operations are intentionally enumeration-safe (no information leak about
/// whether the email exists in the system).
/// </summary>
public interface IPasswordResetService
{
    /// <summary>
    /// Always completes successfully so callers cannot probe for valid emails.
    /// If the email matches an active user, a reset email is dispatched.
    /// </summary>
    Task RequestResetAsync(ForgotPasswordRequestDto request, string? clientIp, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Validates the token and applies the new password. On success, all existing
    /// refresh tokens for the user are invalidated, forcing re-login on every device.
    /// Throws UnauthorizedAccessException for invalid/expired/used tokens.
    /// </summary>
    Task ResetPasswordAsync(ResetPasswordRequestDto request, string? clientIp, string? userAgent, CancellationToken ct = default);
}
