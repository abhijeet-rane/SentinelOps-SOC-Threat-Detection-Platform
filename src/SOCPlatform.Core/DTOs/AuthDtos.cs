namespace SOCPlatform.Core.DTOs;

public class LoginRequestDto
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class LoginResponseDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public UserDto User { get; set; } = null!;

    // ── MFA challenge fields ──
    // When MfaRequired is true, AccessToken / RefreshToken are EMPTY and the
    // caller must exchange MfaToken for a full login via /auth/mfa/verify.
    public bool MfaRequired { get; set; } = false;
    public string? MfaToken { get; set; }
    public bool MfaEnrollmentRequired { get; set; } = false;  // true for priv roles w/o MFA yet
}

// ─── MFA DTOs ───────────────────────────────────────────────────────────────

public class MfaSetupResponseDto
{
    /// <summary>Base-32 encoded secret (show to user as fallback for manual entry).</summary>
    public string SecretBase32 { get; set; } = string.Empty;

    /// <summary>otpauth:// URI the user can paste into an authenticator app.</summary>
    public string OtpAuthUri { get; set; } = string.Empty;

    /// <summary>PNG of the otpauth URI encoded as base64 — render as &lt;img src="data:image/png;base64,...".</summary>
    public string QrCodePngBase64 { get; set; } = string.Empty;
}

public class MfaEnableRequestDto
{
    /// <summary>Six-digit TOTP code from the user's authenticator.</summary>
    public string Code { get; set; } = string.Empty;
}

public class MfaEnableResponseDto
{
    /// <summary>Ten single-use recovery codes. Shown ONCE — user must save them immediately.</summary>
    public List<string> BackupCodes { get; set; } = new();
}

public class MfaDisableRequestDto
{
    public string CurrentPassword { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
}

public class MfaVerifyRequestDto
{
    /// <summary>Short-lived MFA challenge token issued by /auth/login.</summary>
    public string MfaToken { get; set; } = string.Empty;

    /// <summary>Six-digit TOTP code from the user's authenticator.</summary>
    public string Code { get; set; } = string.Empty;
}

public class MfaBackupRequestDto
{
    /// <summary>Short-lived MFA challenge token issued by /auth/login.</summary>
    public string MfaToken { get; set; } = string.Empty;

    /// <summary>One of the backup codes returned at enable-time. Single-use.</summary>
    public string BackupCode { get; set; } = string.Empty;
}

public class MfaStatusDto
{
    public bool Enabled { get; set; }
    public DateTime? EnabledAt { get; set; }
    public int RemainingBackupCodes { get; set; }
}

// ─── First-time enrollment DURING login (bootstrap path) ────────────────────
// A privileged account (SOC Manager / System Administrator) that has never
// enrolled MFA cannot reach the normal /mfa/setup endpoint, because they
// cannot obtain a full access token without MFA. These two DTOs carry the
// short-lived mfaToken from /auth/login so enrollment can be completed
// anonymously in a single guided flow.

public class MfaEnrollSetupRequestDto
{
    /// <summary>Short-lived mfaToken issued by /auth/login when MfaEnrollmentRequired=true.</summary>
    public string MfaToken { get; set; } = string.Empty;
}

public class MfaEnrollCompleteRequestDto
{
    public string MfaToken { get; set; } = string.Empty;
    /// <summary>Six-digit TOTP code from the newly-scanned authenticator app.</summary>
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// Successful response from /auth/mfa/enroll-complete. Contains BOTH the
/// single-use backup codes (shown once) AND a full login envelope so the user
/// goes straight into the authenticated app — no second password prompt.
/// </summary>
public class MfaEnrollCompleteResponseDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public UserDto User { get; set; } = null!;
    public List<string> BackupCodes { get; set; } = new();
}

public class RefreshTokenRequestDto
{
    public string RefreshToken { get; set; } = string.Empty;
}

public class RegisterUserDto
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public Guid RoleId { get; set; }
}

public class UserDto
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public Guid RoleId { get; set; }
    public bool IsActive { get; set; }
    public DateTime? LastLogin { get; set; }
    public DateTime CreatedAt { get; set; }
    public List<string> Permissions { get; set; } = new();
}

public class UpdateUserDto
{
    public Guid? RoleId { get; set; }
    public string? Email { get; set; }
    public bool? IsActive { get; set; }
}

