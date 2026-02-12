using Microsoft.AspNetCore.Authorization;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.API.Authorization;

/// <summary>
/// Requirement that the authenticated user must have a specific permission.
/// Used with the policy-based authorization system.
/// </summary>
public class PermissionRequirement : IAuthorizationRequirement
{
    public Permission Permission { get; }

    public PermissionRequirement(Permission permission)
    {
        Permission = permission;
    }
}

/// <summary>
/// Handles PermissionRequirement by checking JWT "Permission" claims.
/// </summary>
public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        var permissionClaims = context.User.FindAll("Permission");

        if (permissionClaims.Any(c => c.Value == requirement.Permission.ToString()))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
