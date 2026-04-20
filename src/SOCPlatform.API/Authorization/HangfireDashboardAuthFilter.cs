using Hangfire.Dashboard;

namespace SOCPlatform.API.Authorization;

/// <summary>
/// Restricts Hangfire dashboard access to authenticated users in the "Admin" role.
/// </summary>
public sealed class HangfireDashboardAuthFilter : IDashboardAuthorizationFilter
{
    public bool Authorize(DashboardContext context)
    {
        var http = context.GetHttpContext();
        return http.User.Identity?.IsAuthenticated == true && http.User.IsInRole("Admin");
    }
}
