using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SOCPlatform.Core.Entities;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Soar;
using SOCPlatform.Infrastructure.Soar.Adapters;

namespace SOCPlatform.Tests.Soar;

/// <summary>
/// Unit tests for the three simulator adapters. Each verifies:
///   1. AdapterResult.IsSimulated is true (drives "Simulated" badge)
///   2. SimulatedActionLog row is persisted with correct fields
///   3. Latency is captured (>= the simulated 50 ms minimum)
///   4. Successful + failure paths
/// </summary>
public class SimulatedAdapterTests
{
    private static SOCDbContext NewDb()
    {
        var opts = new DbContextOptionsBuilder<SOCDbContext>()
            .UseInMemoryDatabase($"soar-{Guid.NewGuid()}").Options;
        return new SOCDbContext(opts);
    }

    private static SimulatedActionRecorder NewRecorder(SOCDbContext db) =>
        new(db, NullLogger<SimulatedActionRecorder>.Instance);

    // ── Firewall ────────────────────────────────────────────────────────────

    [Fact]
    public async Task SimulatedFirewallAdapter_BlockIp_Persists_Log_And_Returns_Simulated_Result()
    {
        using var db = NewDb();
        var adapter = new SimulatedFirewallAdapter(NewRecorder(db));
        var alertId = Guid.NewGuid();

        var result = await adapter.BlockIpAsync("1.2.3.4", "Brute force from this IP", alertId);

        result.Success.Should().BeTrue();
        result.IsSimulated.Should().BeTrue();
        result.AdapterName.Should().Be("SimulatedFirewallAdapter");
        result.Action.Should().Be("BlockIp");
        result.Target.Should().Be("1.2.3.4");
        result.LatencyMs.Should().BeGreaterOrEqualTo(50);

        var log = await db.SimulatedActionLogs.SingleAsync();
        log.Action.Should().Be("BlockIp");
        log.Target.Should().Be("1.2.3.4");
        log.Reason.Should().Be("Brute force from this IP");
        log.Success.Should().BeTrue();
        log.AlertId.Should().Be(alertId);
        log.LatencyMs.Should().BeGreaterOrEqualTo(50);
    }

    [Fact]
    public async Task SimulatedFirewallAdapter_UnblockIp_Persists_Log()
    {
        using var db = NewDb();
        var adapter = new SimulatedFirewallAdapter(NewRecorder(db));

        await adapter.UnblockIpAsync("1.2.3.4", "False positive", null);

        var log = await db.SimulatedActionLogs.SingleAsync();
        log.Action.Should().Be("UnblockIp");
        log.Target.Should().Be("1.2.3.4");
    }

    // ── Identity ────────────────────────────────────────────────────────────

    [Fact]
    public async Task SimulatedIdentityAdapter_LockAccount_Sets_LockoutEnd_On_Real_User()
    {
        using var db = NewDb();
        var role = new Role { Id = Guid.NewGuid(), Name = "Analyst" };
        var user = new User
        {
            Id = Guid.NewGuid(), Username = "victim", Email = "v@x.com",
            PasswordHash = "x", RoleId = role.Id, IsActive = true
        };
        db.Roles.Add(role); db.Users.Add(user); await db.SaveChangesAsync();

        var adapter = new SimulatedIdentityAdapter(db, NewRecorder(db));
        var result = await adapter.LockAccountAsync("victim", TimeSpan.FromMinutes(15), "Suspicious", null);

        result.Success.Should().BeTrue();
        var refreshed = await db.Users.FirstAsync(u => u.Username == "victim");
        refreshed.LockoutEnd.Should().NotBeNull();
        refreshed.LockoutEnd!.Value.Should().BeAfter(DateTime.UtcNow.AddMinutes(14));
    }

    [Fact]
    public async Task SimulatedIdentityAdapter_LockAccount_Unknown_User_Returns_Failed_Result()
    {
        using var db = NewDb();
        var adapter = new SimulatedIdentityAdapter(db, NewRecorder(db));

        var result = await adapter.LockAccountAsync("ghost", TimeSpan.FromMinutes(5), "n/a", null);

        result.Success.Should().BeFalse();
        result.ErrorDetail.Should().Be("user_not_found");

        var log = await db.SimulatedActionLogs.SingleAsync();
        log.Success.Should().BeFalse();
        log.ErrorDetail.Should().Be("user_not_found");
    }

    [Fact]
    public async Task SimulatedIdentityAdapter_DisableUser_Sets_IsActive_False_And_Wipes_RefreshToken()
    {
        using var db = NewDb();
        var role = new Role { Id = Guid.NewGuid(), Name = "Analyst" };
        var user = new User
        {
            Id = Guid.NewGuid(), Username = "compromised", Email = "c@x.com",
            PasswordHash = "x", RoleId = role.Id, IsActive = true,
            RefreshToken = "stale-token", RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
        };
        db.Roles.Add(role); db.Users.Add(user); await db.SaveChangesAsync();

        var adapter = new SimulatedIdentityAdapter(db, NewRecorder(db));
        var result = await adapter.DisableUserAsync("compromised", "APT", null);

        result.Success.Should().BeTrue();
        var refreshed = await db.Users.FirstAsync(u => u.Username == "compromised");
        refreshed.IsActive.Should().BeFalse();
        refreshed.RefreshToken.Should().BeNull();
        refreshed.RefreshTokenExpiry.Should().BeNull();
    }

    [Fact]
    public async Task SimulatedIdentityAdapter_ResetCredentials_Wipes_PasswordHash()
    {
        using var db = NewDb();
        var role = new Role { Id = Guid.NewGuid(), Name = "Analyst" };
        var oldHash = "OLDHASH";
        var user = new User
        {
            Id = Guid.NewGuid(), Username = "phished", Email = "p@x.com",
            PasswordHash = oldHash, RoleId = role.Id, IsActive = true,
            FailedLoginAttempts = 3, LockoutEnd = DateTime.UtcNow.AddMinutes(15)
        };
        db.Roles.Add(role); db.Users.Add(user); await db.SaveChangesAsync();

        var adapter = new SimulatedIdentityAdapter(db, NewRecorder(db));
        var result = await adapter.ResetCredentialsAsync("phished", "Phishing reported", null);

        result.Success.Should().BeTrue();
        var refreshed = await db.Users.FirstAsync(u => u.Username == "phished");
        refreshed.PasswordHash.Should().NotBe(oldHash);
        refreshed.PasswordHash.Should().StartWith("FORCED-RESET-");
        refreshed.FailedLoginAttempts.Should().Be(0);
        refreshed.LockoutEnd.Should().BeNull();
    }

    // ── Endpoint ────────────────────────────────────────────────────────────

    [Fact]
    public async Task SimulatedEndpointAdapter_Isolate_And_Unisolate_Persist_Logs()
    {
        using var db = NewDb();
        var adapter = new SimulatedEndpointAdapter(NewRecorder(db));

        await adapter.IsolateEndpointAsync("workstation-42", "Ransomware suspected", null);
        await adapter.UnisolateEndpointAsync("workstation-42", "Cleared by analyst", null);

        var logs = await db.SimulatedActionLogs.OrderBy(l => l.ExecutedAt).ToListAsync();
        logs.Should().HaveCount(2);
        logs[0].Action.Should().Be("IsolateEndpoint");
        logs[1].Action.Should().Be("UnisolateEndpoint");
        logs.Should().AllSatisfy(l => l.AdapterName.Should().Be("SimulatedEndpointAdapter"));
    }
}
