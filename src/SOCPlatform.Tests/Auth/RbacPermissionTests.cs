using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Tests.Auth;

/// <summary>
/// RBAC permission matrix integration tests.
/// Uses WebApplicationFactory + Docker PostgreSQL to spin up the real API.
/// Verifies each role gets the right HTTP status for each endpoint,
/// based on the actual [Authorize(Policy = "...")] / [Authorize(Roles = "...")] decorators.
/// </summary>
public class RbacPermissionTests : IClassFixture<SocApiFactory>
{
    private readonly SocApiFactory _factory;

    public RbacPermissionTests(SocApiFactory factory)
        => _factory = factory;

    // ── Helpers ───────────────────────────────────────

    private HttpClient ClientFor(string role) =>
        ClientWithPermissions(role, SocApiFactory.PermissionsFor(role));

    private HttpClient ClientWithPermissions(string role, IEnumerable<string> permissions)
    {
        var client = _factory.CreateClient();
        var token = SocApiFactory.MintTestJwt(role, permissions);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private HttpClient AnonymousClient() => _factory.CreateClient();

    // ── Unauthenticated → 401 ─────────────────────────
    // Covers OWASP A01: Broken Access Control (missing auth = 401)

    [Theory]
    [InlineData("GET",  "/api/alerts")]
    [InlineData("GET",  "/api/incidents")]
    [InlineData("GET",  "/api/dashboard/analytics")]
    [InlineData("GET",  "/api/auditlog")]
    [InlineData("GET",  "/api/ml/status")]
    public async Task Unauthenticated_Request_Returns_401(string method, string path)
    {
        var response = await AnonymousClient()
            .SendAsync(new HttpRequestMessage(new HttpMethod(method), path));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: $"unauthenticated {method} {path} must return 401");
    }

    // ── Alerts: [Authorize] — any valid JWT ───────────

    [Theory]
    [InlineData("Admin")]
    [InlineData("SOC Manager")]
    [InlineData("Analyst")]
    [InlineData("Responder")]
    [InlineData("ReadOnly")]
    public async Task GET_Alerts_Allowed_For_All_Authenticated_Roles(string role)
    {
        var response = await ClientFor(role).GetAsync("/api/alerts");
        response.StatusCode.Should().NotBe(HttpStatusCode.Unauthorized);
        response.StatusCode.Should().NotBe(HttpStatusCode.Forbidden,
            because: $"GET /api/alerts has no policy, role '{role}' should be allowed");
    }

    // ── Reports/daily: [Authorize] — any valid JWT ────
    // The /api/reports/daily action has NO policy attribute — only class-level [Authorize]

    [Theory]
    [InlineData("Admin")]
    [InlineData("SOC Manager")]
    [InlineData("Analyst")]
    [InlineData("Responder")]
    [InlineData("ReadOnly")]
    public async Task GET_Reports_Daily_Allowed_For_All_Authenticated_Roles(string role)
    {
        var response = await ClientFor(role).GetAsync("/api/reports/daily");
        response.StatusCode.Should().NotBe(HttpStatusCode.Unauthorized);
        response.StatusCode.Should().NotBe(HttpStatusCode.Forbidden,
            because: $"GET /api/reports/daily has no action-level policy, role '{role}' should be allowed");
    }

    // ── AuditLog: [Authorize(Policy = "ViewAuditLogs")] ──

    [Theory]
    [InlineData("Admin")]
    [InlineData("SOC Manager")]
    public async Task GET_AuditLog_Allowed_For_Roles_With_ViewAuditLogs_Permission(string role)
    {
        var response = await ClientFor(role).GetAsync("/api/auditlog");
        response.StatusCode.Should().NotBe(HttpStatusCode.Forbidden,
            because: $"role '{role}' has ViewAuditLogs permission");
        response.StatusCode.Should().NotBe(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData("Analyst")]
    [InlineData("Responder")]
    [InlineData("ReadOnly")]
    public async Task GET_AuditLog_Forbidden_For_Roles_Without_ViewAuditLogs_Permission(string role)
    {
        var response = await ClientFor(role).GetAsync("/api/auditlog");
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            because: $"role '{role}' does not have ViewAuditLogs permission");
    }

    // ── Auth/users: [Authorize(Policy = "ManageUsers")] ──

    [Fact]
    public async Task GET_Auth_Users_Allowed_For_Admin_With_ManageUsers_Permission()
    {
        var response = await ClientFor("Admin").GetAsync("/api/auth/users");
        response.StatusCode.Should().NotBe(HttpStatusCode.Forbidden,
            because: "Admin has ManageUsers permission");
        response.StatusCode.Should().NotBe(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData("SOC Manager")]
    [InlineData("Analyst")]
    [InlineData("Responder")]
    [InlineData("ReadOnly")]
    public async Task GET_Auth_Users_Forbidden_For_Roles_Without_ManageUsers_Permission(string role)
    {
        var response = await ClientFor(role).GetAsync("/api/auth/users");
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            because: $"role '{role}' does not have ManageUsers permission");
    }

    // ── ML/train: [Authorize(Roles = "Admin,SOC Manager")] ──

    [Theory]
    [InlineData("Admin")]
    [InlineData("SOC Manager")]
    public async Task POST_ML_Train_Allowed_For_Admin_And_SocManager(string role)
    {
        var content = new StringContent("{\"model\":\"all\"}", Encoding.UTF8, "application/json");
        var response = await ClientFor(role).PostAsync("/api/ml/train", content);
        // 200 OK or 503 (ML Python service offline during tests) — never 401/403
        response.StatusCode.Should().NotBe(HttpStatusCode.Forbidden,
            because: $"role '{role}' matches Roles = 'Admin,SOC Manager' attribute");
        response.StatusCode.Should().NotBe(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData("Analyst")]
    [InlineData("Responder")]
    [InlineData("ReadOnly")]
    public async Task POST_ML_Train_Forbidden_For_Non_Manager_Roles(string role)
    {
        var content = new StringContent("{\"model\":\"all\"}", Encoding.UTF8, "application/json");
        var response = await ClientFor(role).PostAsync("/api/ml/train", content);
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            because: $"role '{role}' is not in Roles = 'Admin,SOC Manager'");
    }
}

/// <summary>
/// Custom WebApplicationFactory that spins up the real API against the Docker
/// PostgreSQL instance, using the same JWT secret as the app config.
/// Background hosted services are suppressed so they don't interfere with tests.
/// </summary>
public class SocApiFactory : WebApplicationFactory<Program>
{
    internal const string TestSecret  = "CHANGE-THIS-IN-PRODUCTION-USE-AT-LEAST-256-BIT-KEY-HERE-SOC-2026";
    private const  string TestIssuer  = "SOCPlatform";
    private const  string TestAudience = "SOCPlatform.Web";

    private const string DockerConnStr =
        "Host=localhost;Port=5433;Database=socplatform;Username=socadmin;Password=SocDev2026;Include Error Detail=true";

    // ── Role → Permission mapping ─────────────────────
    // Mirrors the DatabaseSeeder's RolePermission seed data.
    private static readonly Dictionary<string, Permission[]> RolePermissions = new()
    {
        ["Admin"] = Enum.GetValues<Permission>(),  // All permissions
        ["SOC Manager"] =
        [
            Permission.ViewAlerts, Permission.AcknowledgeAlerts, Permission.InvestigateAlerts,
            Permission.EscalateAlerts, Permission.CreateIncidents, Permission.ResolveIncidents,
            Permission.ViewIncidents, Permission.ViewDashboards, Permission.ViewOperationalKpis,
            Permission.ViewExecutiveReports, Permission.EnableDisableRules, Permission.ManageRules,
            Permission.ExecutePlaybooks, Permission.ApproveResponses,
            Permission.ViewAuditLogs, Permission.ViewSystemHealth,
        ],
        ["Analyst"] =
        [
            Permission.ViewAlerts, Permission.AcknowledgeAlerts, Permission.InvestigateAlerts,
            Permission.EscalateAlerts, Permission.CreateIncidents, Permission.ViewIncidents,
            Permission.ViewDashboards, Permission.ViewOperationalKpis, Permission.ExecutePlaybooks,
        ],
        ["Responder"] =
        [
            Permission.ViewAlerts, Permission.AcknowledgeAlerts, Permission.InvestigateAlerts,
            Permission.EscalateAlerts, Permission.ViewIncidents,
            Permission.ViewDashboards, Permission.ExecutePlaybooks,
        ],
        ["ReadOnly"] =
        [
            Permission.ViewAlerts, Permission.ViewIncidents,
            Permission.ViewDashboards, Permission.ViewOperationalKpis,
        ],
    };

    public static IEnumerable<string> PermissionsFor(string role) =>
        RolePermissions.TryGetValue(role, out var perms)
            ? perms.Select(p => p.ToString())
            : [];

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = DockerConnStr,
                ["JwtSettings:SecretKey"]    = TestSecret,
                ["JwtSettings:Issuer"]       = TestIssuer,
                ["JwtSettings:Audience"]     = TestAudience,
            });
        });

        // Suppress noisy background services that poll the DB on a timer
        builder.ConfigureServices(services =>
        {
            RemoveHostedService<SOCPlatform.Infrastructure.Services.LogRetentionService>(services);
            RemoveHostedService<SOCPlatform.Detection.Playbooks.PlaybookEngine>(services);
        });
    }

    private static void RemoveHostedService<T>(IServiceCollection services) where T : class
    {
        var toRemove = services
            .Where(d => d.ServiceType == typeof(IHostedService)
                     && d.ImplementationType == typeof(T))
            .ToList();
        foreach (var svc in toRemove)
            services.Remove(svc);
    }

    /// <summary>
    /// Mint a JWT with the correct Role + Permission claims that mirror the real login token.
    /// </summary>
    public static string MintTestJwt(
        string role,
        IEnumerable<string>? permissions = null,
        string userId = "00000000-0000-0000-0000-000000000001",
        string username = "testuser")
    {
        var key   = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TestSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Role, role),
            new("RoleId", Guid.NewGuid().ToString()),
        };

        // Add Permission claims — these are what PermissionAuthorizationHandler checks
        foreach (var perm in permissions ?? PermissionsFor(role))
            claims.Add(new Claim("Permission", perm));

        var token = new JwtSecurityToken(
            issuer:             TestIssuer,
            audience:           TestAudience,
            claims:             claims,
            expires:            DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
