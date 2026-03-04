using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Tests;

/// <summary>
/// Shared test utilities: SecurityEvent builder, JWT factory, and common helpers.
/// </summary>
public static class TestHelpers
{
    // ── SecurityEvent Builder ──────────────────────

    /// <summary>Create a LoginFailure event from a given source IP targeting a user.</summary>
    public static SecurityEvent LoginFailure(
        string sourceIp = "192.168.1.100",
        string user = "jdoe",
        string device = "DESKTOP-01",
        DateTime? timestamp = null)
        => new()
        {
            EventCategory = "Security",
            EventAction = "LoginFailure",
            SourceIP = sourceIp,
            AffectedUser = user,
            AffectedDevice = device,
            Severity = "High",
            Timestamp = timestamp ?? DateTime.UtcNow,
        };

    /// <summary>Create a LoginSuccess event.</summary>
    public static SecurityEvent LoginSuccess(
        string user = "jdoe",
        string device = "DESKTOP-01",
        DateTime? timestamp = null)
        => new()
        {
            EventCategory = "Security",
            EventAction = "LoginSuccess",
            AffectedUser = user,
            AffectedDevice = device,
            Severity = "Low",
            Timestamp = timestamp ?? DateTime.UtcNow,
        };

    /// <summary>Create an ActiveConnections event pointing at a specific port.</summary>
    public static SecurityEvent NetworkConnection(
        string sourceIp = "10.0.0.5",
        int destPort = 80,
        string device = "ROUTER-01",
        DateTime? timestamp = null)
        => new()
        {
            EventCategory = "Network",
            EventAction = "ActiveConnections",
            SourceIP = sourceIp,
            DestinationPort = destPort,
            AffectedDevice = device,
            Severity = "Low",
            Timestamp = timestamp ?? DateTime.UtcNow,
        };

    /// <summary>Create a privilege escalation event.</summary>
    public static SecurityEvent PrivilegeEvent(
        string action = "SpecialPrivilegeAssigned",
        string user = "badactor",
        DateTime? timestamp = null)
        => new()
        {
            EventCategory = "Security",
            EventAction = action,
            AffectedUser = user,
            AffectedDevice = "DC-01",
            Severity = "Critical",
            Timestamp = timestamp ?? DateTime.UtcNow,
        };

    /// <summary>Create a file access event in the Security category.</summary>
    public static SecurityEvent FileAccess(
        string user = "intern",
        string category = "Security",
        string sourceIp = "192.168.1.200",
        DateTime? timestamp = null)
        => new()
        {
            EventCategory = category,
            EventAction = "FileAccess",
            AffectedUser = user,
            AffectedDevice = "WS-01",
            SourceIP = sourceIp,
            Severity = "Medium",
            Timestamp = timestamp ?? DateTime.UtcNow,
        };

    /// <summary>Create an event with a known-malicious file hash.</summary>
    public static SecurityEvent MaliciousHashEvent(
        bool isThreatMatch = true,
        string hash = "e3b0c44298fc1c149afb",
        string user = "victim")
        => new()
        {
            EventCategory = "Endpoint",
            EventAction = "ProcessCreate",
            IsThreatIntelMatch = isThreatMatch,
            FileHash = hash,
            AffectedUser = user,
            AffectedDevice = "LAPTOP-99",
            Severity = "Critical",
            Timestamp = DateTime.UtcNow,
        };

    // ── Time helpers ──────────────────────────────

    /// <summary>Returns a UTC DateTime that is guaranteed to be off-hours locally.</summary>
    public static DateTime OffHoursUtc()
    {
        // 02:00 UTC will be off-hours in any timezone within UTC−5 to UTC+5
        var now = DateTime.UtcNow;
        return new DateTime(now.Year, now.Month, now.Day, 2, 0, 0, DateTimeKind.Utc);
    }

    /// <summary>Returns a safe business-hours UTC time (10:00 UTC → 15:30 local for IST).</summary>
    public static DateTime BusinessHoursUtc()
    {
        // The PrivilegeEscalationRule converts to local time, so we need to compute
        // a UTC value that translates to between 08:00-18:00 *local* time.
        // Use noon local today → convert back to UTC.
        var localNoon = new DateTime(DateTime.Today.Year, DateTime.Today.Month, DateTime.Today.Day, 12, 0, 0, DateTimeKind.Local);
        return localNoon.ToUniversalTime();
    }

    /// <summary>Returns a UTC DateTime that maps to outside business hours in local timezone.</summary>
    public static DateTime OffHoursLocal()
    {
        // 03:00 local → UTC (guaranteed off-hours anywhere)
        var localOff = new DateTime(DateTime.Today.Year, DateTime.Today.Month, DateTime.Today.Day, 3, 0, 0, DateTimeKind.Local);
        return localOff.ToUniversalTime();
    }

    // ── JWT Token Factory ─────────────────────────

    private const string TestSecret = "SOCPlatformTestSecretKey-Phase14-Testing-32chars!";

    /// <summary>Mint a short-lived JWT token for a given role for API testing.</summary>
    public static string MintJwt(string role, string userId = "test-user-id", string username = "testuser")
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TestSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, role),
        };

        var token = new JwtSecurityToken(
            issuer: "SOCPlatform",
            audience: "SOCPlatformUsers",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
