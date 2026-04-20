using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Services;

namespace SOCPlatform.Tests.Auth;

/// <summary>
/// Unit tests for PasswordResetService. Uses EF Core InMemory provider for the
/// DbContext and Moq for IEmailSender + IAuditService.
/// </summary>
public class PasswordResetServiceTests
{
    private readonly AuthOptions _authOptions = new()
    {
        PasswordResetTokenLifetimeMinutes = 60,
        FrontendBaseUrl = "http://localhost:5173"
    };

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static SOCDbContext CreateDb()
    {
        var options = new DbContextOptionsBuilder<SOCDbContext>()
            .UseInMemoryDatabase(databaseName: $"prst-{Guid.NewGuid()}")
            .Options;
        return new SOCDbContext(options);
    }

    private (PasswordResetService svc, SOCDbContext db, Mock<IEmailSender> email, Mock<IAuditService> audit)
        CreateService()
    {
        var db = CreateDb();
        var email = new Mock<IEmailSender>();
        var audit = new Mock<IAuditService>();
        audit.Setup(a => a.LogAsync(
            It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>())).Returns(Task.CompletedTask);

        var svc = new PasswordResetService(
            db, email.Object, audit.Object,
            Options.Create(_authOptions),
            NullLogger<PasswordResetService>.Instance);

        return (svc, db, email, audit);
    }

    private static User SeedUser(SOCDbContext db, string email = "alice@example.com", bool active = true)
    {
        var role = new Role { Id = Guid.NewGuid(), Name = "Analyst" };
        db.Roles.Add(role);

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = "alice",
            Email = email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("OriginalP@ss1!", workFactor: 4),
            RoleId = role.Id,
            IsActive = active,
            RefreshToken = "old-refresh-token",
            RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
        };
        db.Users.Add(user);
        db.SaveChanges();
        return user;
    }

    // ── Token hash helpers ──────────────────────────────────────────────────

    [Fact]
    public void HashToken_Is_64_Hex_Chars_Lowercase()
    {
        var hash = PasswordResetService.HashToken("any-plaintext");
        hash.Length.Should().Be(64);
        hash.Should().MatchRegex("^[0-9a-f]{64}$");
    }

    [Fact]
    public void HashToken_Is_Deterministic_For_Same_Input()
    {
        var a = PasswordResetService.HashToken("hello");
        var b = PasswordResetService.HashToken("hello");
        a.Should().Be(b);
    }

    [Fact]
    public void HashToken_Different_Input_Different_Output()
    {
        var a = PasswordResetService.HashToken("hello");
        var b = PasswordResetService.HashToken("world");
        a.Should().NotBe(b);
    }

    // ── RequestResetAsync ───────────────────────────────────────────────────

    [Fact]
    public async Task RequestReset_Unknown_Email_Does_Nothing_But_Doesnt_Throw()
    {
        var (svc, db, email, _) = CreateService();
        await svc.RequestResetAsync(new ForgotPasswordRequestDto { Email = "ghost@nowhere.com" }, "127.0.0.1", "ua");
        (await db.PasswordResetTokens.CountAsync()).Should().Be(0);
        email.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RequestReset_Inactive_User_Does_Not_Send_Email()
    {
        var (svc, db, email, _) = CreateService();
        SeedUser(db, active: false);
        await svc.RequestResetAsync(new ForgotPasswordRequestDto { Email = "alice@example.com" }, null, null);
        (await db.PasswordResetTokens.CountAsync()).Should().Be(0);
        email.Verify(e => e.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RequestReset_Valid_User_Creates_Token_And_Sends_Email()
    {
        var (svc, db, email, audit) = CreateService();
        SeedUser(db);

        await svc.RequestResetAsync(new ForgotPasswordRequestDto { Email = "alice@example.com" }, "10.0.0.5", "TestAgent/1.0");

        var token = await db.PasswordResetTokens.SingleAsync();
        token.TokenHash.Should().HaveLength(64);
        token.UsedAt.Should().BeNull();
        token.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
        token.RequestIpAddress.Should().Be("10.0.0.5");
        token.RequestUserAgent.Should().Be("TestAgent/1.0");

        email.Verify(e => e.SendAsync(
            It.Is<EmailMessage>(m => m.To == "alice@example.com" && m.HtmlBody.Contains("reset-password")),
            It.IsAny<CancellationToken>()), Times.Once);

        audit.Verify(a => a.LogAsync(
            It.IsAny<Guid?>(), "PasswordResetRequested", "User", It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task RequestReset_Email_Lookup_Is_Case_Insensitive()
    {
        var (svc, db, email, _) = CreateService();
        SeedUser(db, email: "alice@example.com");

        await svc.RequestResetAsync(new ForgotPasswordRequestDto { Email = "ALICE@EXAMPLE.COM" }, null, null);

        (await db.PasswordResetTokens.CountAsync()).Should().Be(1);
        email.Verify(e => e.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RequestReset_Twice_Invalidates_Prior_Unused_Token()
    {
        var (svc, db, _, _) = CreateService();
        SeedUser(db);

        await svc.RequestResetAsync(new ForgotPasswordRequestDto { Email = "alice@example.com" }, null, null);
        await svc.RequestResetAsync(new ForgotPasswordRequestDto { Email = "alice@example.com" }, null, null);

        var tokens = await db.PasswordResetTokens.OrderBy(t => t.CreatedAt).ToListAsync();
        tokens.Should().HaveCount(2);
        tokens[0].UsedAt.Should().NotBeNull("first token should be invalidated when a second is issued");
        tokens[1].UsedAt.Should().BeNull();
    }

    // ── ResetPasswordAsync ──────────────────────────────────────────────────

    [Fact]
    public async Task ResetPassword_Empty_Token_Throws_Unauthorized()
    {
        var (svc, _, _, _) = CreateService();
        var act = () => svc.ResetPasswordAsync(new ResetPasswordRequestDto { Token = "", NewPassword = "NewP@ss12345!" }, null, null);
        await act.Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task ResetPassword_Unknown_Token_Throws_Unauthorized()
    {
        var (svc, db, _, _) = CreateService();
        SeedUser(db);
        var act = () => svc.ResetPasswordAsync(new ResetPasswordRequestDto { Token = "nonexistent-token", NewPassword = "NewP@ss12345!" }, null, null);
        await act.Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task ResetPassword_Expired_Token_Throws_Unauthorized()
    {
        var (svc, db, _, _) = CreateService();
        var user = SeedUser(db);
        var plaintext = "expired-token-plaintext-12345";
        db.PasswordResetTokens.Add(new PasswordResetToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = PasswordResetService.HashToken(plaintext),
            CreatedAt = DateTime.UtcNow.AddHours(-2),
            ExpiresAt = DateTime.UtcNow.AddHours(-1)  // expired 1h ago
        });
        await db.SaveChangesAsync();

        var act = () => svc.ResetPasswordAsync(new ResetPasswordRequestDto { Token = plaintext, NewPassword = "NewP@ss12345!" }, "1.1.1.1", null);
        await act.Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task ResetPassword_Already_Used_Token_Throws_Unauthorized()
    {
        var (svc, db, _, _) = CreateService();
        var user = SeedUser(db);
        var plaintext = "used-token-plaintext-12345";
        db.PasswordResetTokens.Add(new PasswordResetToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = PasswordResetService.HashToken(plaintext),
            CreatedAt = DateTime.UtcNow.AddMinutes(-30),
            ExpiresAt = DateTime.UtcNow.AddMinutes(30),
            UsedAt = DateTime.UtcNow.AddMinutes(-5)
        });
        await db.SaveChangesAsync();

        var act = () => svc.ResetPasswordAsync(new ResetPasswordRequestDto { Token = plaintext, NewPassword = "NewP@ss12345!" }, null, null);
        await act.Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task ResetPassword_Valid_Token_Updates_Hash_Burns_Token_Revokes_Refresh_And_Audits()
    {
        var (svc, db, _, audit) = CreateService();
        var user = SeedUser(db);
        var oldHash = user.PasswordHash;
        var plaintext = "good-token-plaintext-67890";

        db.PasswordResetTokens.Add(new PasswordResetToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = PasswordResetService.HashToken(plaintext),
            CreatedAt = DateTime.UtcNow.AddMinutes(-5),
            ExpiresAt = DateTime.UtcNow.AddMinutes(55)
        });
        await db.SaveChangesAsync();

        await svc.ResetPasswordAsync(
            new ResetPasswordRequestDto { Token = plaintext, NewPassword = "BrandNewP@ssword1!" },
            "192.168.1.50", "Mozilla/5.0");

        var refreshed = await db.Users.FirstAsync(u => u.Id == user.Id);
        refreshed.PasswordHash.Should().NotBe(oldHash);
        BCrypt.Net.BCrypt.Verify("BrandNewP@ssword1!", refreshed.PasswordHash).Should().BeTrue();

        // refresh tokens revoked
        refreshed.RefreshToken.Should().BeNull();
        refreshed.RefreshTokenExpiry.Should().BeNull();

        // failed-login state cleared
        refreshed.FailedLoginAttempts.Should().Be(0);
        refreshed.LockoutEnd.Should().BeNull();

        // token burned
        var token = await db.PasswordResetTokens.SingleAsync();
        token.UsedAt.Should().NotBeNull();

        audit.Verify(a => a.LogAsync(
            It.IsAny<Guid?>(), "PasswordReset", "User", It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task ResetPassword_Inactive_User_Throws_Even_With_Valid_Token()
    {
        var (svc, db, _, _) = CreateService();
        var user = SeedUser(db, active: false);
        var plaintext = "valid-but-inactive-12345";
        db.PasswordResetTokens.Add(new PasswordResetToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = PasswordResetService.HashToken(plaintext),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(60)
        });
        await db.SaveChangesAsync();

        var act = () => svc.ResetPasswordAsync(new ResetPasswordRequestDto { Token = plaintext, NewPassword = "GoodP@ss12345!" }, null, null);
        await act.Should().ThrowAsync<UnauthorizedAccessException>();
    }
}
