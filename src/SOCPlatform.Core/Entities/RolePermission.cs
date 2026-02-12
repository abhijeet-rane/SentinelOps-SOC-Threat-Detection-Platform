using SOCPlatform.Core.Enums;

namespace SOCPlatform.Core.Entities;

/// <summary>
/// Maps a permission to a role. Implements granular RBAC.
/// </summary>
public class RolePermission
{
    public Guid Id { get; set; }
    public Guid RoleId { get; set; }
    public Permission Permission { get; set; }

    // Navigation
    public Role Role { get; set; } = null!;
}
