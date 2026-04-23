using SOCPlatform.Core.DTOs;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Authentication service interface for JWT-based auth.
/// </summary>
public interface IAuthService
{
    Task<LoginResponseDto> LoginAsync(LoginRequestDto request);
    Task<LoginResponseDto> RefreshTokenAsync(string refreshToken);
    Task<UserDto> RegisterAsync(RegisterUserDto request, Guid createdBy);
    Task LogoutAsync(Guid userId);
    Task<bool> ValidateTokenAsync(string token);

    // MFA — second-factor exchange after /login has issued an mfaToken.
    Task<LoginResponseDto> CompleteMfaAsync(MfaVerifyRequestDto request);
    Task<LoginResponseDto> CompleteMfaBackupAsync(MfaBackupRequestDto request);

    // MFA — first-time enrollment during login (for accounts that require MFA
    // but haven't enrolled yet). Uses the mfaToken in place of an access token.
    Task<MfaSetupResponseDto> BeginMfaEnrollmentAsync(MfaEnrollSetupRequestDto request);
    Task<MfaEnrollCompleteResponseDto> CompleteMfaEnrollmentAsync(MfaEnrollCompleteRequestDto request);

    // User management
    Task<List<UserDto>> GetAllUsersAsync();
    Task<UserDto> UpdateUserAsync(Guid userId, UpdateUserDto request);
    Task DeactivateUserAsync(Guid userId);
}
