using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Interfaces;

namespace SOCPlatform.API.Controllers;

[ApiController]
[Asp.Versioning.ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IPasswordResetService _passwordReset;

    public AuthController(IAuthService authService, IPasswordResetService passwordReset)
    {
        _authService = authService;
        _passwordReset = passwordReset;
    }

    /// <summary>
    /// Authenticate user with username/password, returns JWT + refresh token.
    /// </summary>
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        try
        {
            var result = await _authService.LoginAsync(request);
            return Ok(ApiResponse<LoginResponseDto>.Ok(result, "Login successful"));
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ApiResponse<object>.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Refresh access token using a valid refresh token.
    /// </summary>
    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto request)
    {
        try
        {
            var result = await _authService.RefreshTokenAsync(request.RefreshToken);
            return Ok(ApiResponse<LoginResponseDto>.Ok(result));
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ApiResponse<object>.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Initiate the password-reset flow. Always returns 202 Accepted regardless
    /// of whether the email exists (to prevent account enumeration). If the email
    /// matches an active account, a reset link is dispatched to it.
    /// </summary>
    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDto request, CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var ua = Request.Headers.UserAgent.ToString();
        await _passwordReset.RequestResetAsync(request, ip, ua, ct);
        return Accepted(ApiResponse<object>.Ok(
            new { },
            "If the email matches an account, a password-reset link has been sent."));
    }

    /// <summary>
    /// Complete the password-reset flow with the emailed token + new password.
    /// On success, all refresh tokens for the user are invalidated (re-login required).
    /// </summary>
    [HttpPost("reset-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDto request, CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var ua = Request.Headers.UserAgent.ToString();
        try
        {
            await _passwordReset.ResetPasswordAsync(request, ip, ua, ct);
            return Ok(ApiResponse<object>.Ok(
                new { },
                "Password reset successful. Please log in with your new password."));
        }
        catch (UnauthorizedAccessException ex)
        {
            return BadRequest(ApiResponse<object>.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Register a new user (Admin only).
    /// </summary>
    [HttpPost("register")]
    [Authorize(Policy = "ManageUsers")]
    public async Task<IActionResult> Register([FromBody] RegisterUserDto request)
    {
        try
        {
            var createdBy = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            var user = await _authService.RegisterAsync(request, createdBy);
            return CreatedAtAction(nameof(GetProfile), null, ApiResponse<UserDto>.Ok(user, "User created"));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(ApiResponse<object>.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Get current authenticated user's profile.
    /// </summary>
    [HttpGet("profile")]
    [Authorize]
    public IActionResult GetProfile()
    {
        var user = new UserDto
        {
            Id = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!),
            Username = User.FindFirstValue(ClaimTypes.Name)!,
            Email = User.FindFirstValue(ClaimTypes.Email)!,
            Role = User.FindFirstValue(ClaimTypes.Role)!,
            RoleId = Guid.Parse(User.FindFirstValue("RoleId")!),
            Permissions = User.FindAll("Permission").Select(c => c.Value).ToList()
        };

        return Ok(ApiResponse<UserDto>.Ok(user));
    }

    /// <summary>
    /// Logout the current user (invalidates refresh token).
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _authService.LogoutAsync(userId);
        return Ok(ApiResponse<object>.Ok(new { }, "Logged out successfully"));
    }

    // ── User Management (Admin) ──

    /// <summary>
    /// Get all users with roles and status (Admin only).
    /// </summary>
    [HttpGet("users")]
    [Authorize(Policy = "ManageUsers")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _authService.GetAllUsersAsync();
        return Ok(ApiResponse<List<UserDto>>.Ok(users));
    }

    /// <summary>
    /// Update a user's role or active status (Admin only).
    /// </summary>
    [HttpPut("users/{id:guid}")]
    [Authorize(Policy = "ManageUsers")]
    public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserDto request)
    {
        try
        {
            var user = await _authService.UpdateUserAsync(id, request);
            return Ok(ApiResponse<UserDto>.Ok(user, "User updated"));
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(ApiResponse<object>.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Deactivate a user account (Admin only).
    /// </summary>
    [HttpPatch("users/{id:guid}/deactivate")]
    [Authorize(Policy = "ManageUsers")]
    public async Task<IActionResult> DeactivateUser(Guid id)
    {
        try
        {
            await _authService.DeactivateUserAsync(id);
            return Ok(ApiResponse<object>.Ok(new { }, "User deactivated"));
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(ApiResponse<object>.Fail(ex.Message));
        }
    }
}

