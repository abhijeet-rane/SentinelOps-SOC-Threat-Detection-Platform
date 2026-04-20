namespace SOCPlatform.Core.Soar;

/// <summary>
/// Identity provider integration: lock accounts, disable users, force credential rotation.
/// Real implementations: Azure AD Graph · Okta · Auth0 · local DB.
/// </summary>
public interface IIdentityAdapter
{
    string Name { get; }
    bool IsSimulated { get; }

    /// <summary>Temporarily lock an account for the given duration.</summary>
    Task<AdapterResult> LockAccountAsync(string username, TimeSpan duration, string reason, Guid? alertId, CancellationToken ct = default);

    /// <summary>Permanently disable an account (requires manual re-enable).</summary>
    Task<AdapterResult> DisableUserAsync(string username, string reason, Guid? alertId, CancellationToken ct = default);

    /// <summary>Invalidate all sessions and force a password change at next login.</summary>
    Task<AdapterResult> ResetCredentialsAsync(string username, string reason, Guid? alertId, CancellationToken ct = default);
}
