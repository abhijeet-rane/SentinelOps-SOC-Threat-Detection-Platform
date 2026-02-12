using Microsoft.AspNetCore.Authorization;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.API.Authorization;

/// <summary>
/// Extension methods to register permission-based authorization policies.
/// Each Permission enum value gets a corresponding named policy.
/// </summary>
public static class AuthorizationPolicies
{
    public static void AddPermissionPolicies(this AuthorizationOptions options)
    {
        // Generate a policy for every Permission enum value
        foreach (Permission permission in Enum.GetValues<Permission>())
        {
            options.AddPolicy(permission.ToString(), policy =>
                policy.Requirements.Add(new PermissionRequirement(permission)));
        }
    }
}
