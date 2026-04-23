using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.DataProtection;
using OtpNet;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Services;

namespace SOCPlatform.Tests.Auth;

/// <summary>
/// Unit-level tests for MfaService. Uses EF Core InMemory + ephemeral Data
/// Protection (no persisted keys) + a stub IAuditService so we can exercise
/// the full TOTP / backup-code machinery without hitting Postgres.
/// </summary>
public class MfaServiceTests
{
    private readonly SOCDbContext _db;
    private readonly IMfaService _mfa;
    private readonly IDataProtector _protector;
    private readonly Guid _userId = Guid.NewGuid();

    public MfaServiceTests()
    {
        var opts = new DbContextOptionsBuilder<SOCDbContext>()
            .UseInMemoryDatabase($"mfa-{Guid.NewGuid()}")
            .Options;
        _db = new SOCDbContext(opts);

        var services = new ServiceCollection().AddDataProtection().Services.BuildServiceProvider();
        var dpp = services.GetRequiredService<IDataProtectionProvider>();
        _protector = dpp.CreateProtector("SentinelOps.Mfa.TotpSecret.v1");

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["JwtSettings:Issuer"] = "SentinelOps" })
            .Build();

        _mfa = new MfaService(_db, dpp, new StubAudit(), cfg, NullLogger<MfaService>.Instance);

        // Seed a minimal user. Role/navigation not needed for MFA flows.
        _db.Users.Add(new User
        {
            Id = _userId,
            Username = "mfauser",
            Email = "mfa@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("CurrentP@ss1!", workFactor: 4),
            RoleId = Guid.NewGuid(),
            IsActive = true,
        });
        _db.SaveChanges();
    }

    private string CurrentCode()
    {
        var u = _db.Users.AsNoTracking().First(x => x.Id == _userId);
        var secret = _protector.Unprotect(u.MfaSecret!);
        return new Totp(secret).ComputeTotp();
    }

    // ── Happy path ────────────────────────────────────────────────────────
    [Fact]
    public async Task Setup_then_Enable_happy_path()
    {
        var setup = await _mfa.GenerateSetupAsync(_userId);
        setup.SecretBase32.Should().NotBeNullOrWhiteSpace();
        setup.OtpAuthUri.Should().StartWith("otpauth://totp/");
        setup.QrCodePngBase64.Should().NotBeEmpty();

        var enable = await _mfa.EnableAsync(_userId, CurrentCode());
        enable.BackupCodes.Should().HaveCount(10);
        enable.BackupCodes.Should().OnlyContain(c => c.Length >= 8);

        var status = await _mfa.GetStatusAsync(_userId);
        status.Enabled.Should().BeTrue();
        status.RemainingBackupCodes.Should().Be(10);
    }

    // ── Verify: wrong code rejected, right code accepted ─────────────────
    [Fact]
    public async Task Verify_rejects_wrong_code()
    {
        await _mfa.GenerateSetupAsync(_userId);
        await _mfa.EnableAsync(_userId, CurrentCode());

        (await _mfa.VerifyCodeAsync(_userId, "000000")).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_accepts_current_code()
    {
        await _mfa.GenerateSetupAsync(_userId);
        await _mfa.EnableAsync(_userId, CurrentCode());

        (await _mfa.VerifyCodeAsync(_userId, CurrentCode())).Should().BeTrue();
    }

    // ── Non-digit / wrong-length inputs are rejected cleanly ─────────────
    [Theory]
    [InlineData("abcdef")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("")]
    [InlineData(" ")]
    public async Task Verify_rejects_malformed_code(string code)
    {
        await _mfa.GenerateSetupAsync(_userId);
        await _mfa.EnableAsync(_userId, CurrentCode());

        (await _mfa.VerifyCodeAsync(_userId, code)).Should().BeFalse();
    }

    // ── Enable with wrong code does not flip MfaEnabled ──────────────────
    [Fact]
    public async Task Enable_with_wrong_code_throws_and_stays_disabled()
    {
        await _mfa.GenerateSetupAsync(_userId);

        await FluentActions.Invoking(() => _mfa.EnableAsync(_userId, "000000"))
            .Should().ThrowAsync<UnauthorizedAccessException>();

        var status = await _mfa.GetStatusAsync(_userId);
        status.Enabled.Should().BeFalse();
    }

    // ── Backup code: single-use ───────────────────────────────────────────
    [Fact]
    public async Task Backup_code_is_single_use()
    {
        await _mfa.GenerateSetupAsync(_userId);
        var enable = await _mfa.EnableAsync(_userId, CurrentCode());
        var code = enable.BackupCodes.First();

        (await _mfa.ConsumeBackupCodeAsync(_userId, code)).Should().BeTrue();
        (await _mfa.ConsumeBackupCodeAsync(_userId, code)).Should().BeFalse();

        var status = await _mfa.GetStatusAsync(_userId);
        status.RemainingBackupCodes.Should().Be(9);
    }

    [Fact]
    public async Task Backup_code_rejects_unknown_value()
    {
        await _mfa.GenerateSetupAsync(_userId);
        await _mfa.EnableAsync(_userId, CurrentCode());

        (await _mfa.ConsumeBackupCodeAsync(_userId, "NOT-A-CODE")).Should().BeFalse();
    }

    // ── Disable requires password + TOTP ─────────────────────────────────
    [Fact]
    public async Task Disable_clears_state_on_success()
    {
        await _mfa.GenerateSetupAsync(_userId);
        await _mfa.EnableAsync(_userId, CurrentCode());

        await _mfa.DisableAsync(_userId, "CurrentP@ss1!", CurrentCode());

        var u = await _db.Users.FirstAsync(x => x.Id == _userId);
        u.MfaEnabled.Should().BeFalse();
        u.MfaSecret.Should().BeNull();
        u.MfaBackupCodes.Should().BeEmpty();
    }

    [Fact]
    public async Task Disable_rejects_wrong_password()
    {
        await _mfa.GenerateSetupAsync(_userId);
        await _mfa.EnableAsync(_userId, CurrentCode());

        await FluentActions.Invoking(() => _mfa.DisableAsync(_userId, "wrong", CurrentCode()))
            .Should().ThrowAsync<UnauthorizedAccessException>();

        (await _mfa.GetStatusAsync(_userId)).Enabled.Should().BeTrue();
    }

    // ── Re-setup while enabled is rejected ───────────────────────────────
    [Fact]
    public async Task GenerateSetup_rejects_when_already_enabled()
    {
        await _mfa.GenerateSetupAsync(_userId);
        await _mfa.EnableAsync(_userId, CurrentCode());

        await FluentActions.Invoking(() => _mfa.GenerateSetupAsync(_userId))
            .Should().ThrowAsync<InvalidOperationException>();
    }

    // ── Enable without Setup rejected ────────────────────────────────────
    [Fact]
    public async Task Enable_without_Setup_rejected()
    {
        await FluentActions.Invoking(() => _mfa.EnableAsync(_userId, "123456"))
            .Should().ThrowAsync<InvalidOperationException>();
    }

    // ── Secret is encrypted at rest (not the raw value) ──────────────────
    [Fact]
    public async Task Secret_is_encrypted_at_rest()
    {
        var setup = await _mfa.GenerateSetupAsync(_userId);
        var u = await _db.Users.FirstAsync(x => x.Id == _userId);

        var raw = Base32Encoding.ToBytes(setup.SecretBase32);
        u.MfaSecret.Should().NotBeNull();
        u.MfaSecret!.SequenceEqual(raw).Should().BeFalse("persisted secret must be ciphertext, not plaintext");
        // Round-trips through the protector
        _protector.Unprotect(u.MfaSecret).Should().Equal(raw);
    }

    // Stub audit service so tests don't require the interceptor + chain.
    private sealed class StubAudit : IAuditService
    {
        public Task LogAsync(Guid? userId, string action, string resource, string? resourceId = null,
            string? oldValue = null, string? newValue = null, string? ipAddress = null, string? userAgent = null,
            string? details = null) => Task.CompletedTask;
        public Task<bool> VerifyChainIntegrityAsync() => Task.FromResult(true);
    }
}
