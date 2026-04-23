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
    private readonly IMfaService _mfa;
    private readonly ILogger<AuthService> _logger;

    private const int MaxFailedAttempts = 5;
    private const int LockoutMinutes = 15;
    // MFA-challenge tokens carry a dedicated audience so they can't be used
    // against normal protected endpoints. 5 min is plenty for the user to
    // retrieve and type a code without being so long it's risky if stolen.
    private const string MfaAudience = "SOCPlatform.Mfa";
    private const int MfaTokenMinutes = 5;

    // Roles that MUST have MFA enabled — enforced at login.
    private static readonly HashSet<string> MfaRequiredRoles =
        new(StringComparer.OrdinalIgnoreCase) { "SOC Manager", "System Administrator" };

    public AuthService(
        SOCDbContext context,
        IConfiguration configuration,
        IAuditService auditService,
        IMfaService mfa,
        ILogger<AuthService> logger)
    {
        _context = context;
        _configuration = configuration;
        _auditService = auditService;
        _mfa = mfa;
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

        // Password is correct. Reset lockout counters immediately so a stolen
        // password that still needs MFA doesn't also keep the account locked.
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;

        // ── MFA branch ───────────────────────────────────────────────────
        // Privileged roles must have MFA enabled. If they don't, we refuse
        // to issue a full JWT and tell the client to enroll first.
        var mustHaveMfa = MfaRequiredRoles.Contains(user.Role.Name);

        if (mustHaveMfa && !user.MfaEnabled)
        {
            await _context.SaveChangesAsync();
            await _auditService.LogAsync(user.Id, "MfaEnrollmentForced", "User", user.Id.ToString(),
                details: $"Role '{user.Role.Name}' requires MFA enrollment before login can complete.");
            _logger.LogInformation(
                "Login held for user '{Username}': role {Role} requires MFA enrollment",
                user.Username, user.Role.Name);

            return new LoginResponseDto
            {
                MfaRequired = true,
                MfaEnrollmentRequired = true,
                MfaToken = GenerateMfaChallengeToken(user),
                User = MapToUserDto(user),
            };
        }

        if (user.MfaEnabled)
        {
            await _context.SaveChangesAsync();
            _logger.LogInformation("User '{Username}' passed password; awaiting MFA", user.Username);

            return new LoginResponseDto
            {
                MfaRequired = true,
                MfaToken = GenerateMfaChallengeToken(user),
            };
        }

        // ── No MFA required → issue full tokens immediately ───────────────
        return await IssueFullLoginAsync(user);
    }

    private async Task<LoginResponseDto> IssueFullLoginAsync(User user)
    {
        user.LastLogin = DateTime.UtcNow;

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

    // ── MFA challenge exchange ───────────────────────────────────────────

    public async Task<LoginResponseDto> CompleteMfaAsync(MfaVerifyRequestDto request)
    {
        var userId = ValidateMfaChallengeToken(request.MfaToken);
        var user = await LoadUserForLoginAsync(userId);

        if (!user.MfaEnabled)
            throw new UnauthorizedAccessException("MFA is not enabled for this user");

        if (!await _mfa.VerifyCodeAsync(user.Id, request.Code))
            throw new UnauthorizedAccessException("Invalid MFA code");

        return await IssueFullLoginAsync(user);
    }

    public async Task<LoginResponseDto> CompleteMfaBackupAsync(MfaBackupRequestDto request)
    {
        var userId = ValidateMfaChallengeToken(request.MfaToken);
        var user = await LoadUserForLoginAsync(userId);

        if (!user.MfaEnabled)
            throw new UnauthorizedAccessException("MFA is not enabled for this user");

        if (!await _mfa.ConsumeBackupCodeAsync(user.Id, request.BackupCode))
            throw new UnauthorizedAccessException("Invalid backup code");

        return await IssueFullLoginAsync(user);
    }

    // ── First-time enrollment during login ───────────────────────────────

    public async Task<MfaSetupResponseDto> BeginMfaEnrollmentAsync(MfaEnrollSetupRequestDto request)
    {
        // The mfaToken alone is authentication for this bootstrap flow — it
        // was issued by a successful password check moments ago, so we trust
        // the sub claim to identify the enrolling user.
        var userId = ValidateMfaChallengeToken(request.MfaToken);
        var user = await LoadUserForLoginAsync(userId);

        if (user.MfaEnabled)
            throw new InvalidOperationException("MFA is already enabled. Log in and use Settings → Security.");

        return await _mfa.GenerateSetupAsync(user.Id);
    }

    public async Task<MfaEnrollCompleteResponseDto> CompleteMfaEnrollmentAsync(MfaEnrollCompleteRequestDto request)
    {
        var userId = ValidateMfaChallengeToken(request.MfaToken);
        var user = await LoadUserForLoginAsync(userId);

        if (user.MfaEnabled)
            throw new InvalidOperationException("MFA is already enabled. Please log in again.");

        // Verifies the TOTP, flips MfaEnabled=true, generates + persists 10
        // BCrypt-hashed backup codes, and returns the plaintext codes once.
        var enable = await _mfa.EnableAsync(user.Id, request.Code);

        // Reload because EnableAsync saved the MFA fields; the in-memory
        // instance we hold may be stale wrt MfaEnabledAt etc.
        user = await LoadUserForLoginAsync(userId);

        // Drop the user straight into the app with full tokens — otherwise
        // they'd have to log in again and immediately redo MFA verification.
        var login = await IssueFullLoginAsync(user);

        return new MfaEnrollCompleteResponseDto
        {
            AccessToken = login.AccessToken,
            RefreshToken = login.RefreshToken,
            ExpiresAt = login.ExpiresAt,
            User = login.User,
            BackupCodes = enable.BackupCodes,
        };
    }

    private async Task<User> LoadUserForLoginAsync(Guid userId)
    {
        var user = await _context.Users
            .Include(u => u.Role)
            .ThenInclude(r => r.Permissions)
            .FirstOrDefaultAsync(u => u.Id == userId)
            ?? throw new UnauthorizedAccessException("User not found");

        if (!user.IsActive)
            throw new UnauthorizedAccessException("Account is deactivated");

        return user;
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

    // ── MFA challenge-token helpers ──────────────────────────────────────
    // This is a short-lived JWT with a dedicated audience so it cannot
    // authenticate to normal protected endpoints — only to /auth/mfa/verify
    // and /auth/mfa/backup.

    private string GenerateMfaChallengeToken(User user)
    {
        var jwt = _configuration.GetSection("JwtSettings");
        var secret = Encoding.UTF8.GetBytes(jwt["SecretKey"]!);
        var creds = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new("mfaPending", "true"),
        };

        var token = new JwtSecurityToken(
            issuer: jwt["Issuer"],
            audience: MfaAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(MfaTokenMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private Guid ValidateMfaChallengeToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new UnauthorizedAccessException("MFA token missing");

        var jwt = _configuration.GetSection("JwtSettings");
        var secret = Encoding.UTF8.GetBytes(jwt["SecretKey"]!);
        var handler = new JwtSecurityTokenHandler();

        try
        {
            var principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwt["Issuer"],
                ValidAudience = MfaAudience,
                IssuerSigningKey = new SymmetricSecurityKey(secret),
                ClockSkew = TimeSpan.FromSeconds(30),
            }, out _);

            var mfaFlag = principal.FindFirst("mfaPending")?.Value;
            if (!string.Equals(mfaFlag, "true", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Token is not an MFA challenge token");

            var sub = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                      ?? throw new UnauthorizedAccessException("MFA token missing sub claim");
            return Guid.Parse(sub);
        }
        catch (SecurityTokenExpiredException)
        {
            throw new UnauthorizedAccessException("MFA challenge expired. Start login again.");
        }
        // Catch both SecurityTokenException (signature / audience / issuer /
        // lifetime failures) and ArgumentException (malformed non-JWT input
        // like "not-a-real-token" — the handler throws ArgumentException
        // before it can fail the signature check). Either way: 401.
        catch (Exception ex) when (ex is SecurityTokenException or ArgumentException)
        {
            _logger.LogWarning(ex, "Invalid MFA challenge token");
            throw new UnauthorizedAccessException("Invalid MFA token");
        }
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
