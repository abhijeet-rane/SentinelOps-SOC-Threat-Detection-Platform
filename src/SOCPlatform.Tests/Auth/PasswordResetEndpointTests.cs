using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Services;

namespace SOCPlatform.Tests.Auth;

/// <summary>
/// Integration tests for /api/v1/auth/forgot-password and /api/v1/auth/reset-password.
/// Uses the existing SocApiFactory which targets the real Postgres in docker.
/// In the same xunit collection as RbacPermissionTests so the two share the
/// real database serially — avoids cold-start migration/seed races in CI.
/// </summary>
[Collection("DatabaseIntegration")]
public class PasswordResetEndpointTests : IClassFixture<SocApiFactory>, IAsyncLifetime
{
    private readonly SocApiFactory _factory;

    public PasswordResetEndpointTests(SocApiFactory factory) => _factory = factory;

    private string _email = $"pwreset-{Guid.NewGuid():N}@example.com";
    private string _username = $"pwreset-{Guid.NewGuid():N}"[..30];
    private Guid _userId;

    public async Task InitializeAsync()
    {
        // Seed a dedicated test user so we don't disturb the default admin.
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
        var anyRole = await db.Roles.FirstAsync();

        var u = new User
        {
            Id = Guid.NewGuid(),
            Username = _username,
            Email = _email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("OriginalP@ss1!", workFactor: 4),
            RoleId = anyRole.Id,
            IsActive = true,
            RefreshToken = "stale-refresh"
        };
        db.Users.Add(u);
        await db.SaveChangesAsync();
        _userId = u.Id;
    }

    public async Task DisposeAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
        var u = await db.Users.FindAsync(_userId);
        if (u is not null)
        {
            db.PasswordResetTokens.RemoveRange(db.PasswordResetTokens.Where(t => t.UserId == _userId));
            db.Users.Remove(u);
            await db.SaveChangesAsync();
        }
    }

    [Fact]
    public async Task ForgotPassword_Unknown_Email_Returns_202_And_Creates_No_Token()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync(
            "/api/v1/auth/forgot-password",
            new ForgotPasswordRequestDto { Email = "ghost-no-such-user@example.com" });

        resp.StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
        (await db.PasswordResetTokens
            .CountAsync(t => t.User.Email == "ghost-no-such-user@example.com")).Should().Be(0);
    }

    [Fact]
    public async Task ForgotPassword_Known_Email_Returns_202_And_Creates_Token()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync(
            "/api/v1/auth/forgot-password",
            new ForgotPasswordRequestDto { Email = _email });

        resp.StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
        var token = await db.PasswordResetTokens.SingleAsync(t => t.UserId == _userId && t.UsedAt == null);
        token.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task ResetPassword_Invalid_Token_Returns_400()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync(
            "/api/v1/auth/reset-password",
            new ResetPasswordRequestDto { Token = "definitely-not-a-real-token-xx", NewPassword = "NewG00d!Pass" });

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ResetPassword_Weak_Password_Fails_Validation()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync(
            "/api/v1/auth/reset-password",
            new ResetPasswordRequestDto { Token = "any-token-with-enough-length", NewPassword = "weak" });

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task End_To_End_Reset_Then_Login_With_New_Password_Works()
    {
        var client = _factory.CreateClient();

        // 1. Issue forgot-password
        var forgot = await client.PostAsJsonAsync(
            "/api/v1/auth/forgot-password",
            new ForgotPasswordRequestDto { Email = _email });
        forgot.StatusCode.Should().Be(HttpStatusCode.Accepted);

        // 2. Read the hashed token directly from the DB and find a matching plaintext.
        //    We cannot recover the plaintext from the hash, so we mint our own:
        //    overwrite the row with a known hash to simulate "received via email".
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
            var token = await db.PasswordResetTokens.SingleAsync(t => t.UserId == _userId && t.UsedAt == null);
            token.TokenHash = PasswordResetService.HashToken("known-plaintext-for-test-12345");
            await db.SaveChangesAsync();
        }

        // 3. Reset using known plaintext
        var reset = await client.PostAsJsonAsync(
            "/api/v1/auth/reset-password",
            new ResetPasswordRequestDto { Token = "known-plaintext-for-test-12345", NewPassword = "BrandNewP@ssw0rd!" });
        reset.StatusCode.Should().Be(HttpStatusCode.OK);

        // 4. Verify password actually changed and refresh token revoked
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
            var u = await db.Users.FirstAsync(x => x.Id == _userId);
            BCrypt.Net.BCrypt.Verify("BrandNewP@ssw0rd!", u.PasswordHash).Should().BeTrue();
            u.RefreshToken.Should().BeNull();
        }

        // 5. Login with new password should succeed
        var login = await client.PostAsJsonAsync(
            "/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = "BrandNewP@ssw0rd!" });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ResetPassword_Reusing_Token_Returns_400_The_Second_Time()
    {
        var client = _factory.CreateClient();

        await client.PostAsJsonAsync(
            "/api/v1/auth/forgot-password",
            new ForgotPasswordRequestDto { Email = _email });

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
            var token = await db.PasswordResetTokens.SingleAsync(t => t.UserId == _userId && t.UsedAt == null);
            token.TokenHash = PasswordResetService.HashToken("reuse-test-plaintext-12345");
            await db.SaveChangesAsync();
        }

        var first = await client.PostAsJsonAsync(
            "/api/v1/auth/reset-password",
            new ResetPasswordRequestDto { Token = "reuse-test-plaintext-12345", NewPassword = "FirstNewP@ss12!" });
        first.StatusCode.Should().Be(HttpStatusCode.OK);

        var second = await client.PostAsJsonAsync(
            "/api/v1/auth/reset-password",
            new ResetPasswordRequestDto { Token = "reuse-test-plaintext-12345", NewPassword = "SecondNewP@ss34!" });
        second.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
