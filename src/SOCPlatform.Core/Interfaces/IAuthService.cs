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

    // User management
    Task<List<UserDto>> GetAllUsersAsync();
    Task<UserDto> UpdateUserAsync(Guid userId, UpdateUserDto request);
    Task DeactivateUserAsync(Guid userId);
}
