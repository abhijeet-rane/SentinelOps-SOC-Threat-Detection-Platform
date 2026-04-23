using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OtpNet;
using QRCoder;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// TOTP MFA service backed by Otp.NET + QRCoder + ASP.NET Data Protection.
///
/// Secret storage: the 160-bit TOTP shared secret never leaves this service
/// in plaintext once persisted. We use a <see cref="IDataProtector"/> with a
/// dedicated purpose string so a DB leak alone can't produce valid codes —
/// the attacker needs the data-protection keys too.
///
/// Backup codes: 10 URL-safe base64 strings, BCrypt-hashed at rest with the
/// same workFactor=12 used for passwords. Single-use — removed from the list
/// on consumption.
/// </summary>
public class MfaService : IMfaService
{
    private const int BackupCodeCount       = 10;
    private const int BackupCodeByteLength  = 6;  // 6 bytes → ~8 base64url chars
    private const int Totp30SecondWindow    = 1;  // ±30 s tolerance
    private const int BcryptWorkFactor      = 12;
    private const string DataProtectorPurpose = "SentinelOps.Mfa.TotpSecret.v1";

    private readonly SOCDbContext _db;
    private readonly IDataProtector _protector;
    private readonly IAuditService _audit;
    private readonly ILogger<MfaService> _logger;
    private readonly string _issuer;

    public MfaService(
        SOCDbContext db,
        IDataProtectionProvider protectionProvider,
        IAuditService audit,
        IConfiguration configuration,
        ILogger<MfaService> logger)
    {
        _db = db;
        _protector = protectionProvider.CreateProtector(DataProtectorPurpose);
        _audit = audit;
        _logger = logger;
        _issuer = configuration["JwtSettings:Issuer"] ?? "SentinelOps";
    }

    // ── GenerateSetup ────────────────────────────────────────────────────
    public async Task<MfaSetupResponseDto> GenerateSetupAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
                   ?? throw new KeyNotFoundException($"User {userId} not found");

        if (user.MfaEnabled)
            throw new InvalidOperationException("MFA is already enabled. Disable it first before re-enrolling.");

        // 160-bit secret (RFC 6238 §5.1 recommends ≥ 128 bits for SHA-1).
        var secret = KeyGeneration.GenerateRandomKey(20);
        user.MfaSecret = _protector.Protect(secret);
        await _db.SaveChangesAsync(ct);

        var secretBase32 = Base32Encoding.ToString(secret);
        var label = Uri.EscapeDataString($"{_issuer}:{user.Email}");
        var issuer = Uri.EscapeDataString(_issuer);
        var otpAuthUri = $"otpauth://totp/{label}?secret={secretBase32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";

        using var qrGen = new QRCodeGenerator();
        using var data = qrGen.CreateQrCode(otpAuthUri, QRCodeGenerator.ECCLevel.M);
        using var png = new PngByteQRCode(data);
        var pngBytes = png.GetGraphic(pixelsPerModule: 6);
        var base64 = Convert.ToBase64String(pngBytes);

        await _audit.LogAsync(userId, "MfaSetupInitiated", "User", userId.ToString());

        return new MfaSetupResponseDto
        {
            SecretBase32 = secretBase32,
            OtpAuthUri = otpAuthUri,
            QrCodePngBase64 = base64,
        };
    }

    // ── Enable ───────────────────────────────────────────────────────────
    public async Task<MfaEnableResponseDto> EnableAsync(Guid userId, string code, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
                   ?? throw new KeyNotFoundException($"User {userId} not found");

        if (user.MfaSecret is null)
            throw new InvalidOperationException("No pending MFA secret. Call /mfa/setup first.");

        if (user.MfaEnabled)
            throw new InvalidOperationException("MFA is already enabled.");

        if (!ValidateCode(user.MfaSecret, code))
        {
            _logger.LogWarning("MFA enable rejected: invalid code for user {UserId}", userId);
            throw new UnauthorizedAccessException("Invalid TOTP code");
        }

        // Generate backup codes. Plaintext returned ONCE; hashes persisted.
        var plaintextCodes = Enumerable.Range(0, BackupCodeCount)
            .Select(_ => NewBackupCode())
            .ToList();
        user.MfaBackupCodes = plaintextCodes
            .Select(c => BCrypt.Net.BCrypt.HashPassword(c, BcryptWorkFactor))
            .ToList();

        user.MfaEnabled = true;
        user.MfaEnabledAt = DateTime.UtcNow;
        user.MfaFailedAttempts = 0;
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(userId, "MfaEnabled", "User", userId.ToString(),
            details: $"User enabled TOTP MFA; {BackupCodeCount} backup codes issued.");

        _logger.LogInformation("MFA enabled for user {UserId}", userId);

        return new MfaEnableResponseDto { BackupCodes = plaintextCodes };
    }

    // ── Disable ──────────────────────────────────────────────────────────
    public async Task DisableAsync(Guid userId, string currentPassword, string totpCode, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
                   ?? throw new KeyNotFoundException($"User {userId} not found");

        if (!user.MfaEnabled)
            throw new InvalidOperationException("MFA is not enabled.");

        if (!BCrypt.Net.BCrypt.Verify(currentPassword, user.PasswordHash))
            throw new UnauthorizedAccessException("Invalid current password");

        if (!ValidateCode(user.MfaSecret!, totpCode))
            throw new UnauthorizedAccessException("Invalid TOTP code");

        user.MfaSecret = null;
        user.MfaEnabled = false;
        user.MfaEnabledAt = null;
        user.MfaBackupCodes = new List<string>();
        user.MfaFailedAttempts = 0;
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(userId, "MfaDisabled", "User", userId.ToString());
        _logger.LogInformation("MFA disabled for user {UserId}", userId);
    }

    // ── Verify TOTP (login flow) ─────────────────────────────────────────
    public async Task<bool> VerifyCodeAsync(Guid userId, string code, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || !user.MfaEnabled || user.MfaSecret is null)
            return false;

        if (ValidateCode(user.MfaSecret, code))
        {
            user.MfaFailedAttempts = 0;
            await _db.SaveChangesAsync(ct);
            await _audit.LogAsync(userId, "MfaVerifySuccess", "User", userId.ToString());
            return true;
        }

        user.MfaFailedAttempts++;
        await _db.SaveChangesAsync(ct);
        _logger.LogWarning("MFA verify failed for user {UserId} (attempt #{Attempt})",
            userId, user.MfaFailedAttempts);
        await _audit.LogAsync(userId, "MfaVerifyFailed", "User", userId.ToString(),
            details: $"Failed attempt #{user.MfaFailedAttempts}");
        return false;
    }

    // ── Consume backup code ──────────────────────────────────────────────
    public async Task<bool> ConsumeBackupCodeAsync(Guid userId, string backupCode, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || !user.MfaEnabled || user.MfaBackupCodes.Count == 0)
            return false;

        var trimmed = (backupCode ?? "").Trim();
        var matchedHash = user.MfaBackupCodes.FirstOrDefault(h => BCrypt.Net.BCrypt.Verify(trimmed, h));
        if (matchedHash is null)
        {
            user.MfaFailedAttempts++;
            await _db.SaveChangesAsync(ct);
            await _audit.LogAsync(userId, "MfaBackupCodeFailed", "User", userId.ToString());
            return false;
        }

        // Consume — single-use.
        user.MfaBackupCodes = user.MfaBackupCodes.Where(h => h != matchedHash).ToList();
        user.MfaFailedAttempts = 0;
        await _db.SaveChangesAsync(ct);
        await _audit.LogAsync(userId, "MfaBackupCodeUsed", "User", userId.ToString(),
            details: $"{user.MfaBackupCodes.Count} backup code(s) remaining");
        _logger.LogInformation("Backup code consumed for user {UserId}; {Remaining} remain",
            userId, user.MfaBackupCodes.Count);
        return true;
    }

    // ── Status ───────────────────────────────────────────────────────────
    public async Task<MfaStatusDto> GetStatusAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new KeyNotFoundException($"User {userId} not found");

        return new MfaStatusDto
        {
            Enabled = user.MfaEnabled,
            EnabledAt = user.MfaEnabledAt,
            RemainingBackupCodes = user.MfaBackupCodes.Count,
        };
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private bool ValidateCode(byte[] protectedSecret, string code)
    {
        if (string.IsNullOrWhiteSpace(code)) return false;
        var cleaned = code.Trim().Replace(" ", "");
        if (cleaned.Length != 6 || !cleaned.All(char.IsDigit)) return false;

        byte[] secret;
        try
        {
            secret = _protector.Unprotect(protectedSecret);
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Failed to unprotect MFA secret — data-protection keys rotated?");
            return false;
        }

        var totp = new Totp(secret, step: 30, mode: OtpHashMode.Sha1, totpSize: 6);
        return totp.VerifyTotp(cleaned, out _, new VerificationWindow(previous: Totp30SecondWindow, future: Totp30SecondWindow));
    }

    private static string NewBackupCode()
    {
        var bytes = RandomNumberGenerator.GetBytes(BackupCodeByteLength);
        // URL-safe base64 without padding; upper-cased for readability on paper.
        var s = Convert.ToBase64String(bytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=')
            .ToUpperInvariant();
        // Insert a dash in the middle for readability: XXXX-XXXX
        return s.Length > 4 ? $"{s[..4]}-{s[4..]}" : s;
    }
}
