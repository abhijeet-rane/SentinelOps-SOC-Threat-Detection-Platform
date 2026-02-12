using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// JWT-based authentication service.
/// Handles login, token generation/refresh, account lockout, and session management.
/// </summary>
public class AuthService : IAuthService
{
    private readonly SOCDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly IAuditService _auditService;
    private readonly ILogger<AuthService> _logger;

    private const int MaxFailedAttempts = 5;
    private const int LockoutMinutes = 15;

    public AuthService(
        SOCDbContext context,
        IConfiguration configuration,
        IAuditService auditService,
        ILogger<AuthService> logger)
    {
        _context = context;
        _configuration = configuration;
        _auditService = auditService;
        _logger = logger;
    }

    public async Task<LoginResponseDto> LoginAsync(LoginRequestDto request)
    {
        var user = await _context.Users
            .Include(u => u.Role)
            .ThenInclude(r => r.Permissions)
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null)
        {
            _logger.LogWarning("Login failed: user '{Username}' not found", request.Username);
            throw new UnauthorizedAccessException("Invalid username or password");
        }

        // Check lockout
        if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
        {
            var remainingMinutes = (user.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes;
            _logger.LogWarning("Login denied: user '{Username}' is locked out for {Minutes:F0} more minutes",
                user.Username, remainingMinutes);
            throw new UnauthorizedAccessException(
                $"Account is locked. Try again in {remainingMinutes:F0} minutes.");
        }

        // Check active status
        if (!user.IsActive)
        {
            throw new UnauthorizedAccessException("Account is deactivated. Contact your administrator.");
        }

        // Verify password
        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            user.FailedLoginAttempts++;

            if (user.FailedLoginAttempts >= MaxFailedAttempts)
            {
                user.LockoutEnd = DateTime.UtcNow.AddMinutes(LockoutMinutes);
                _logger.LogWarning("Account '{Username}' locked after {Count} failed attempts",
                    user.Username, user.FailedLoginAttempts);
                await _auditService.LogAsync(user.Id, "AccountLocked", "User", user.Id.ToString(),
                    details: $"Locked after {user.FailedLoginAttempts} failed login attempts");
            }

            await _context.SaveChangesAsync();
            throw new UnauthorizedAccessException("Invalid username or password");
        }

        // Successful login – reset lockout counters
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        user.LastLogin = DateTime.UtcNow;

        // Generate tokens
        var accessToken = GenerateAccessToken(user);
        var refreshToken = GenerateRefreshToken();

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(
            _configuration.GetValue<int>("JwtSettings:RefreshTokenExpirationDays", 7));

        await _context.SaveChangesAsync();

        await _auditService.LogAsync(user.Id, "Login", "User", user.Id.ToString());
        _logger.LogInformation("User '{Username}' logged in successfully", user.Username);

        return new LoginResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(
                _configuration.GetValue<int>("JwtSettings:AccessTokenExpirationMinutes", 15)),
            User = MapToUserDto(user)
        };
    }

    public async Task<LoginResponseDto> RefreshTokenAsync(string refreshToken)
    {
        var user = await _context.Users
            .Include(u => u.Role)
            .ThenInclude(r => r.Permissions)
            .FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);

        if (user == null || user.RefreshTokenExpiry <= DateTime.UtcNow)
        {
            throw new UnauthorizedAccessException("Invalid or expired refresh token");
        }

        if (!user.IsActive)
        {
            throw new UnauthorizedAccessException("Account is deactivated");
        }

        // Rotate refresh token (one-time use)
        var newAccessToken = GenerateAccessToken(user);
        var newRefreshToken = GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(
            _configuration.GetValue<int>("JwtSettings:RefreshTokenExpirationDays", 7));

        await _context.SaveChangesAsync();

        return new LoginResponseDto
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(
                _configuration.GetValue<int>("JwtSettings:AccessTokenExpirationMinutes", 15)),
            User = MapToUserDto(user)
        };
    }

    public async Task<UserDto> RegisterAsync(RegisterUserDto request, Guid createdBy)
    {
        // Check for duplicate username/email
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            throw new InvalidOperationException($"Username '{request.Username}' is already taken");

        if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            throw new InvalidOperationException($"Email '{request.Email}' is already registered");

        var role = await _context.Roles.FindAsync(request.RoleId)
            ?? throw new InvalidOperationException("Invalid role specified");

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = request.Username,
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password, workFactor: 12),
            RoleId = request.RoleId,
            IsActive = true
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        await _auditService.LogAsync(createdBy, "UserCreated", "User", user.Id.ToString(),
            newValue: $"Username: {user.Username}, Role: {role.Name}");

        // Reload with role for DTO mapping
        user.Role = role;
        role.Permissions = await _context.RolePermissions
            .Where(rp => rp.RoleId == role.Id)
            .ToListAsync();

        return MapToUserDto(user);
    }

    public async Task LogoutAsync(Guid userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user != null)
        {
            user.RefreshToken = null;
            user.RefreshTokenExpiry = null;
            await _context.SaveChangesAsync();
            await _auditService.LogAsync(userId, "Logout", "User", userId.ToString());
        }
    }

    public Task<bool> ValidateTokenAsync(string token)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!);

        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["Issuer"],
                ValidAudience = jwtSettings["Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(secretKey),
                ClockSkew = TimeSpan.Zero
            }, out _);
            return Task.FromResult(true);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }

    // ── User Management ──

    public async Task<List<UserDto>> GetAllUsersAsync()
    {
        var users = await _context.Users
            .Include(u => u.Role)
            .ThenInclude(r => r.Permissions)
            .OrderBy(u => u.Username)
            .AsNoTracking()
            .ToListAsync();

        return users.Select(MapToUserDto).ToList();
    }

    public async Task<UserDto> UpdateUserAsync(Guid userId, UpdateUserDto request)
    {
        var user = await _context.Users
            .Include(u => u.Role)
            .ThenInclude(r => r.Permissions)
            .FirstOrDefaultAsync(u => u.Id == userId)
            ?? throw new KeyNotFoundException($"User {userId} not found");

        if (request.RoleId.HasValue)
        {
            var role = await _context.Roles.FindAsync(request.RoleId.Value)
                ?? throw new InvalidOperationException("Invalid role specified");
            user.RoleId = request.RoleId.Value;
            user.Role = role;
            role.Permissions = await _context.RolePermissions
                .Where(rp => rp.RoleId == role.Id)
                .ToListAsync();
        }

        if (request.Email != null) user.Email = request.Email;
        if (request.IsActive.HasValue) user.IsActive = request.IsActive.Value;

        await _context.SaveChangesAsync();
        _logger.LogInformation("User '{Username}' updated by admin", user.Username);

        return MapToUserDto(user);
    }

    public async Task DeactivateUserAsync(Guid userId)
    {
        var user = await _context.Users.FindAsync(userId)
            ?? throw new KeyNotFoundException($"User {userId} not found");

        user.IsActive = false;
        user.RefreshToken = null;
        user.RefreshTokenExpiry = null;
        await _context.SaveChangesAsync();

        _logger.LogInformation("User '{Username}' deactivated", user.Username);
    }

    // ──────────────────────────────────────────────────
    //  Private helpers
    // ──────────────────────────────────────────────────

    private string GenerateAccessToken(User user)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!);
        var expMinutes = _configuration.GetValue<int>("JwtSettings:AccessTokenExpirationMinutes", 15);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Role, user.Role.Name),
            new("RoleId", user.RoleId.ToString())
        };

        // Embed permissions as individual claims
        foreach (var rp in user.Role.Permissions)
        {
            claims.Add(new Claim("Permission", rp.Permission.ToString()));
        }

        var signingKey = new SymmetricSecurityKey(secretKey);
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    private static UserDto MapToUserDto(User user)
    {
        return new UserDto
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            Role = user.Role.Name,
            RoleId = user.RoleId,
            IsActive = user.IsActive,
            LastLogin = user.LastLogin,
            CreatedAt = user.CreatedAt,
            Permissions = user.Role.Permissions.Select(p => p.Permission.ToString()).ToList()
        };
    }
}
