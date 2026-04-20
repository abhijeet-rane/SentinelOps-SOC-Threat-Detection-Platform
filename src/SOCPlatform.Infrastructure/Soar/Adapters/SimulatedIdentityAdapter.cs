using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.Soar;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Soar.Adapters;

/// <summary>
/// Simulated identity provider. Unlike the firewall/endpoint simulators,
/// this one DOES mutate the local Users table (LockoutEnd, IsActive,
/// RefreshToken) — there's no external IdP to call yet, but the platform's
/// own users are real, so the lock/disable/reset effects are observable.
/// </summary>
public sealed class SimulatedIdentityAdapter : IIdentityAdapter
{
    public string Name => nameof(SimulatedIdentityAdapter);
    public bool IsSimulated => true;

    private readonly SOCDbContext _db;
    private readonly SimulatedActionRecorder _recorder;

    public SimulatedIdentityAdapter(SOCDbContext db, SimulatedActionRecorder recorder)
    {
        _db = db;
        _recorder = recorder;
    }

    public Task<AdapterResult> LockAccountAsync(string username, TimeSpan duration, string reason, Guid? alertId, CancellationToken ct = default) =>
        _recorder.RecordAsync(Name, "LockAccount", username, reason, alertId, async () =>
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == username, ct);
            if (user is null)
                return (false, $"User '{username}' not found", null, "user_not_found");

            user.LockoutEnd = DateTime.UtcNow.Add(duration);
            user.UpdatedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync(ct);

            return (true,
                $"Account '{username}' locked for {duration.TotalMinutes:F0} minutes",
                new Dictionary<string, object>
                {
                    ["lockoutEnd"] = user.LockoutEnd!,
                    ["durationMinutes"] = duration.TotalMinutes
                },
                null);
        }, ct);

    public Task<AdapterResult> DisableUserAsync(string username, string reason, Guid? alertId, CancellationToken ct = default) =>
        _recorder.RecordAsync(Name, "DisableUser", username, reason, alertId, async () =>
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == username, ct);
            if (user is null)
                return (false, $"User '{username}' not found", null, "user_not_found");

            user.IsActive = false;
            user.RefreshToken = null;
            user.RefreshTokenExpiry = null;
            user.UpdatedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync(ct);

            return (true,
                $"Account '{username}' disabled and all sessions revoked",
                null, null);
        }, ct);

    public Task<AdapterResult> ResetCredentialsAsync(string username, string reason, Guid? alertId, CancellationToken ct = default) =>
        _recorder.RecordAsync(Name, "ResetCredentials", username, reason, alertId, async () =>
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == username, ct);
            if (user is null)
                return (false, $"User '{username}' not found", null, "user_not_found");

            // Force re-login on every device + clear lockout state. The user MUST go
            // through the password-reset flow to regain access.
            user.RefreshToken = null;
            user.RefreshTokenExpiry = null;
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            user.UpdatedAt = DateTime.UtcNow;

            // Wipe the password hash — they cannot login until they reset.
            user.PasswordHash = "FORCED-RESET-" + Guid.NewGuid().ToString("N");
            await _db.SaveChangesAsync(ct);

            return (true,
                $"Credentials invalidated for '{username}' — user must use forgot-password flow",
                null, null);
        }, ct);
}
