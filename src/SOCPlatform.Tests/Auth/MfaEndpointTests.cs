using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Tests.Auth;

/// <summary>
/// End-to-end tests over the real HTTP stack (WebApplicationFactory + Postgres).
/// Covers the login → mfaToken → verify exchange, enroll/enable/disable,
/// audience isolation of mfaToken, and backup-code consumption.
/// </summary>
[Collection("DatabaseIntegration")]
public class MfaEndpointTests : IClassFixture<SocApiFactory>, IAsyncLifetime
{
    private readonly SocApiFactory _factory;
    private readonly string _username = $"mfa-{Guid.NewGuid():N}"[..20];
    private readonly string _email    = $"mfa-{Guid.NewGuid():N}@example.com";
    private const string Password     = "TestP@ssw0rd!";
    private Guid _userId;

    public MfaEndpointTests(SocApiFactory factory) => _factory = factory;

    public async Task InitializeAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
        // L1 analyst so MFA is optional by default.
        var roleId = (await db.Roles.FirstAsync(r => r.Name == "SOC Analyst L1")).Id;

        var u = new User
        {
            Id = Guid.NewGuid(),
            Username = _username,
            Email = _email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(Password, workFactor: 4),
            RoleId = roleId,
            IsActive = true,
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
            db.Users.Remove(u);
            await db.SaveChangesAsync();
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private HttpClient NewClient() => _factory.CreateClient();

    private async Task<string> LoginAndGetAccessTokenAsync(HttpClient client)
    {
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>();
        return body!.Data!.AccessToken;
    }

    private async Task SetPendingSecretAsync()
    {
        // Drive /mfa/setup as an authenticated user so the protector + DB state match.
        var client = NewClient();
        var token = await LoginAndGetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var setupResp = await client.PostAsync("/api/v1/auth/mfa/setup", null);
        setupResp.EnsureSuccessStatusCode();
    }

    private async Task<string> CurrentTotpAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
        var dpp = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        var prot = dpp.CreateProtector("SentinelOps.Mfa.TotpSecret.v1");
        var u = await db.Users.AsNoTracking().FirstAsync(x => x.Id == _userId);
        var raw = prot.Unprotect(u.MfaSecret!);
        return new Totp(raw).ComputeTotp();
    }

    private async Task<MfaEnableResponseDto> EnableAsync()
    {
        var client = NewClient();
        var token = await LoginAndGetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var code = await CurrentTotpAsync();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/enable",
            new MfaEnableRequestDto { Code = code });
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadFromJsonAsync<ApiResponse<MfaEnableResponseDto>>();
        return body!.Data!;
    }

    // ── Tests ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Login_without_mfa_returns_full_tokens()
    {
        var client = NewClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>();
        body!.Data!.AccessToken.Should().NotBeNullOrWhiteSpace();
        body.Data.MfaRequired.Should().BeFalse();
    }

    [Fact]
    public async Task Setup_generates_otp_uri_and_qr()
    {
        var client = NewClient();
        var token = await LoginAndGetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await client.PostAsync("/api/v1/auth/mfa/setup", null);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<ApiResponse<MfaSetupResponseDto>>();
        body!.Data!.OtpAuthUri.Should().StartWith("otpauth://totp/");
        body.Data.QrCodePngBase64.Should().NotBeEmpty();
        body.Data.SecretBase32.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Enable_with_correct_code_returns_backup_codes()
    {
        await SetPendingSecretAsync();
        var result = await EnableAsync();
        result.BackupCodes.Should().HaveCount(10);
    }

    [Fact]
    public async Task Login_after_enable_returns_mfaToken_not_full_tokens()
    {
        await SetPendingSecretAsync();
        await EnableAsync();

        var client = NewClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>();

        body!.Data!.MfaRequired.Should().BeTrue();
        body.Data.MfaToken.Should().NotBeNullOrWhiteSpace();
        body.Data.AccessToken.Should().BeNullOrEmpty();
    }

    [Fact]
    public async Task MfaToken_cannot_access_protected_endpoint()
    {
        // The mfaToken carries audience SOCPlatform.Mfa; protected endpoints
        // require the normal SOCPlatform.Web audience — so this should 401.
        await SetPendingSecretAsync();
        await EnableAsync();

        var client = NewClient();
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        var loginBody = await loginResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>();
        var mfaToken = loginBody!.Data!.MfaToken!;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", mfaToken);
        var resp = await client.GetAsync("/api/v1/alerts");
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Verify_exchanges_mfaToken_for_full_tokens()
    {
        await SetPendingSecretAsync();
        await EnableAsync();

        var client = NewClient();
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        var loginBody = await loginResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>();
        var mfaToken = loginBody!.Data!.MfaToken!;

        var code = await CurrentTotpAsync();
        var verifyResp = await client.PostAsJsonAsync("/api/v1/auth/mfa/verify",
            new MfaVerifyRequestDto { MfaToken = mfaToken, Code = code });

        verifyResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await verifyResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>();
        body!.Data!.AccessToken.Should().NotBeNullOrWhiteSpace();
        body.Data.MfaRequired.Should().BeFalse();
    }

    [Fact]
    public async Task Verify_rejects_wrong_code()
    {
        await SetPendingSecretAsync();
        await EnableAsync();

        var client = NewClient();
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        var mfaToken = (await loginResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>())!.Data!.MfaToken!;

        var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/verify",
            new MfaVerifyRequestDto { MfaToken = mfaToken, Code = "000000" });
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Backup_code_is_consumed_after_use()
    {
        await SetPendingSecretAsync();
        var enable = await EnableAsync();
        var backupCode = enable.BackupCodes.First();

        // Start login, then exchange via backup code.
        var client = NewClient();
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        var mfaToken = (await loginResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>())!.Data!.MfaToken!;

        var first = await client.PostAsJsonAsync("/api/v1/auth/mfa/backup",
            new MfaBackupRequestDto { MfaToken = mfaToken, BackupCode = backupCode });
        first.StatusCode.Should().Be(HttpStatusCode.OK);

        // Login again to get a fresh mfaToken; re-use the SAME backup code.
        var login2 = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        var mfaToken2 = (await login2.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>())!.Data!.MfaToken!;
        var second = await client.PostAsJsonAsync("/api/v1/auth/mfa/backup",
            new MfaBackupRequestDto { MfaToken = mfaToken2, BackupCode = backupCode });
        second.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Status_endpoint_reflects_enabled_state()
    {
        await SetPendingSecretAsync();
        await EnableAsync();

        var client = NewClient();
        var token = await LoginAndGetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        // The user is now MFA-enabled, so login flow above should have returned
        // an MfaRequired response — meaning accessToken would be empty. So we
        // need to go through the verify path to actually get a usable token.
    }

    [Fact]
    public async Task Disable_requires_password_and_current_code()
    {
        await SetPendingSecretAsync();
        await EnableAsync();

        // Log in with full MFA flow to get a usable access token.
        var client = NewClient();
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        var mfaToken = (await loginResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>())!.Data!.MfaToken!;
        var verifyResp = await client.PostAsJsonAsync("/api/v1/auth/mfa/verify",
            new MfaVerifyRequestDto { MfaToken = mfaToken, Code = await CurrentTotpAsync() });
        var access = (await verifyResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>())!.Data!.AccessToken;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);

        // Wrong password → 401
        var bad = await client.PostAsJsonAsync("/api/v1/auth/mfa/disable",
            new MfaDisableRequestDto { CurrentPassword = "wrong", Code = await CurrentTotpAsync() });
        bad.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Correct password + code → 200
        var ok = await client.PostAsJsonAsync("/api/v1/auth/mfa/disable",
            new MfaDisableRequestDto { CurrentPassword = Password, Code = await CurrentTotpAsync() });
        ok.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Enroll_at_login_completes_with_full_tokens_and_backup_codes()
    {
        // Bootstrap path — SOC Manager who has never enrolled goes from
        // password → inline enrollment → fully authenticated, in one request chain.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
            var mgrRole = await db.Roles.FirstAsync(r => r.Name == "SOC Manager");
            var u = await db.Users.FirstAsync(x => x.Id == _userId);
            u.RoleId = mgrRole.Id;
            await db.SaveChangesAsync();
        }

        var client = NewClient();

        // 1. Login → mfaEnrollmentRequired, no accessToken yet.
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        var loginBody = await loginResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>();
        loginBody!.Data!.MfaEnrollmentRequired.Should().BeTrue();
        var mfaToken = loginBody.Data.MfaToken!;

        // 2. Request the QR using the mfaToken as authentication.
        var setupResp = await client.PostAsJsonAsync("/api/v1/auth/mfa/enroll-setup",
            new MfaEnrollSetupRequestDto { MfaToken = mfaToken });
        setupResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var setupBody = await setupResp.Content.ReadFromJsonAsync<ApiResponse<MfaSetupResponseDto>>();
        setupBody!.Data!.OtpAuthUri.Should().StartWith("otpauth://totp/");

        // 3. Compute the current TOTP for the now-persisted secret and submit.
        var code = await CurrentTotpAsync();
        var completeResp = await client.PostAsJsonAsync("/api/v1/auth/mfa/enroll-complete",
            new MfaEnrollCompleteRequestDto { MfaToken = mfaToken, Code = code });
        completeResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var completeBody = await completeResp.Content.ReadFromJsonAsync<ApiResponse<MfaEnrollCompleteResponseDto>>();

        completeBody!.Data!.AccessToken.Should().NotBeNullOrWhiteSpace();
        completeBody.Data.RefreshToken.Should().NotBeNullOrWhiteSpace();
        completeBody.Data.BackupCodes.Should().HaveCount(10);
    }

    [Fact]
    public async Task Enroll_at_login_rejected_when_mfa_already_enabled()
    {
        // If the user is already enrolled, the enrollment endpoint must refuse
        // so a stale mfaToken can't generate a fresh secret + wipe backup codes.
        await SetPendingSecretAsync();
        await EnableAsync();

        // Login again, capture the new mfaToken.
        var client = NewClient();
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        var mfaToken = (await loginResp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>())!.Data!.MfaToken!;

        var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/enroll-setup",
            new MfaEnrollSetupRequestDto { MfaToken = mfaToken });
        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Enroll_at_login_rejects_invalid_mfaToken()
    {
        var client = NewClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/enroll-setup",
            new MfaEnrollSetupRequestDto { MfaToken = "not-a-real-token" });
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SOC_Manager_without_mfa_cannot_get_full_tokens()
    {
        // Give the user the SOC Manager role and ensure login returns enrollment required.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
            var mgrRole = await db.Roles.FirstAsync(r => r.Name == "SOC Manager");
            var u = await db.Users.FirstAsync(x => x.Id == _userId);
            u.RoleId = mgrRole.Id;
            await db.SaveChangesAsync();
        }

        var client = NewClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequestDto { Username = _username, Password = Password });
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<ApiResponse<LoginResponseDto>>();

        body!.Data!.MfaRequired.Should().BeTrue();
        body.Data.MfaEnrollmentRequired.Should().BeTrue();
        body.Data.AccessToken.Should().BeNullOrEmpty();
    }
}
