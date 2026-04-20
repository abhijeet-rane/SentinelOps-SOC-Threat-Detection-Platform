using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// Self-service password reset. Token storage uses SHA-256 of a 32-byte CSPRNG
/// secret (the plaintext is only seen once, in the email). Tokens are single-use,
/// time-limited, and on successful reset every refresh token for the user is
/// invalidated, forcing re-login on every device.
/// </summary>
public sealed class PasswordResetService : IPasswordResetService
{
    private const int TokenByteLength = 32;

    private readonly SOCDbContext _db;
    private readonly IEmailSender _email;
    private readonly IAuditService _audit;
    private readonly AuthOptions _authOptions;
    private readonly ILogger<PasswordResetService> _logger;

    public PasswordResetService(
        SOCDbContext db,
        IEmailSender email,
        IAuditService audit,
        IOptions<AuthOptions> authOptions,
        ILogger<PasswordResetService> logger)
    {
        _db = db;
        _email = email;
        _audit = audit;
        _authOptions = authOptions.Value;
        _logger = logger;
    }

    public async Task RequestResetAsync(
        ForgotPasswordRequestDto request,
        string? clientIp,
        string? userAgent,
        CancellationToken ct = default)
    {
        var email = (request.Email ?? string.Empty).Trim().ToLowerInvariant();

        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == email, ct);

        // Enumeration-safe: do NOT reveal whether the email exists.
        if (user is null || !user.IsActive)
        {
            _logger.LogInformation(
                "Password-reset requested for unknown/inactive email {Email} from {Ip}",
                email, clientIp);
            return;
        }

        // Invalidate any prior unused tokens for this user (single outstanding token at a time).
        var pending = await _db.PasswordResetTokens
            .Where(t => t.UserId == user.Id && t.UsedAt == null && t.ExpiresAt > DateTime.UtcNow)
            .ToListAsync(ct);
        foreach (var p in pending) p.UsedAt = DateTime.UtcNow;

        var (plaintextToken, hash) = GenerateToken();

        var record = new PasswordResetToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = hash,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_authOptions.PasswordResetTokenLifetimeMinutes),
            RequestIpAddress = Truncate(clientIp, 45),
            RequestUserAgent = Truncate(userAgent, 500)
        };
        _db.PasswordResetTokens.Add(record);
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(
            user.Id, "PasswordResetRequested", "User", user.Id.ToString(),
            details: $"From IP {clientIp ?? "?"} · token expires {record.ExpiresAt:O}");

        var resetUrl = $"{_authOptions.FrontendBaseUrl.TrimEnd('/')}/reset-password?token={Uri.EscapeDataString(plaintextToken)}";
        var msg = BuildEmail(user, resetUrl, record.ExpiresAt);

        try
        {
            await _email.SendAsync(msg, ct);
            _logger.LogInformation("Password-reset email dispatched to user {UserId}", user.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password-reset email for user {UserId}", user.Id);
            // Don't surface the error to the caller — keep enumeration safety intact.
        }
    }

    public async Task ResetPasswordAsync(
        ResetPasswordRequestDto request,
        string? clientIp,
        string? userAgent,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
            throw new UnauthorizedAccessException("Invalid or expired reset token.");

        var hash = HashToken(request.Token);

        var record = await _db.PasswordResetTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (record is null || record.UsedAt is not null || record.ExpiresAt <= DateTime.UtcNow)
        {
            // Best-effort audit even on failure (helps detect token-guessing attempts).
            if (record?.User is not null)
            {
                await _audit.LogAsync(
                    record.User.Id, "PasswordResetFailed", "User", record.User.Id.ToString(),
                    details: $"From IP {clientIp ?? "?"} · {(record.UsedAt is not null ? "token already used" : "token expired")}");
            }
            else
            {
                _logger.LogWarning("Password-reset attempt with unknown token from {Ip}", clientIp);
            }
            throw new UnauthorizedAccessException("Invalid or expired reset token.");
        }

        var user = record.User;
        if (!user.IsActive)
            throw new UnauthorizedAccessException("Account is deactivated.");

        // Apply new password
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword, workFactor: 12);
        user.UpdatedAt = DateTime.UtcNow;

        // Reset failed-login state
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;

        // Revoke every refresh token for this user (forces re-login everywhere)
        user.RefreshToken = null;
        user.RefreshTokenExpiry = null;

        // Burn this token (single use)
        record.UsedAt = DateTime.UtcNow;

        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(
            user.Id, "PasswordReset", "User", user.Id.ToString(),
            details: $"Password reset succeeded from IP {clientIp ?? "?"}");

        _logger.LogInformation(
            "Password reset succeeded for user {UserId} from {Ip}", user.Id, clientIp);
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Helpers
    // ────────────────────────────────────────────────────────────────────────

    private static (string plaintext, string hash) GenerateToken()
    {
        Span<byte> bytes = stackalloc byte[TokenByteLength];
        RandomNumberGenerator.Fill(bytes);
        // URL-safe base64 (no '+', '/', '=')
        var plaintext = Convert.ToBase64String(bytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return (plaintext, HashToken(plaintext));
    }

    public static string HashToken(string plaintext)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(plaintext), hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? Truncate(string? value, int max) =>
        value is null ? null : value.Length <= max ? value : value[..max];

    private EmailMessage BuildEmail(User user, string resetUrl, DateTime expiresAtUtc)
    {
        var ttlMinutes = _authOptions.PasswordResetTokenLifetimeMinutes;

        var html = $$"""
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"></head>
        <body style="font-family:Segoe UI,Helvetica,Arial,sans-serif;background:#0b1320;color:#e8edf5;padding:24px;">
          <div style="max-width:560px;margin:0 auto;background:#101a2e;border:1px solid #1f2c44;border-radius:10px;padding:28px 24px;">
            <h2 style="margin:0 0 12px 0;color:#5fb4ff;">SentinelOps · Password Reset</h2>
            <p style="margin:0 0 16px 0;">Hi <strong>{{user.Username}}</strong>,</p>
            <p style="margin:0 0 16px 0;">
              We received a request to reset the password on your SentinelOps account.
              Click the button below to choose a new password. This link expires in
              <strong>{{ttlMinutes}} minutes</strong> ({{expiresAtUtc:u}}).
            </p>
            <p style="margin:24px 0;text-align:center;">
              <a href="{{resetUrl}}"
                 style="background:#2563eb;color:#fff;text-decoration:none;font-weight:600;padding:12px 22px;border-radius:8px;display:inline-block;">
                 Reset password
              </a>
            </p>
            <p style="margin:16px 0;color:#a3b1c6;font-size:13px;">
              If the button doesn't work, copy this URL into your browser:<br>
              <span style="color:#5fb4ff;word-break:break-all;">{{resetUrl}}</span>
            </p>
            <hr style="border:0;border-top:1px solid #1f2c44;margin:24px 0;">
            <p style="margin:0;color:#a3b1c6;font-size:12px;">
              If you did <strong>not</strong> request this reset, you can safely ignore this email —
              your password will not change. For your security, this attempt has been recorded
              in the SentinelOps audit log.
            </p>
          </div>
          <p style="text-align:center;color:#6b7a93;font-size:11px;margin-top:18px;">
            SentinelOps SOC · automated message — do not reply
          </p>
        </body></html>
        """;

        var text =
            $"SentinelOps · Password Reset\n\n" +
            $"Hi {user.Username},\n\n" +
            $"To reset your password, open the following link (valid for {ttlMinutes} minutes, expires {expiresAtUtc:u}):\n\n" +
            $"{resetUrl}\n\n" +
            $"If you didn't request this, ignore this email — your password will not change.\n";

        return new EmailMessage(
            To: user.Email,
            ToName: user.Username,
            Subject: "Reset your SentinelOps password",
            HtmlBody: html,
            PlainTextBody: text);
    }
}
