using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace SOCPlatform.API.Hubs;

/// <summary>
/// SignalR hub for real-time alert streaming. All methods require a valid JWT
/// (same Bearer token used for REST). JWT over SignalR: the client passes the
/// token via `?access_token=...` (configured in Program.cs JwtBearerEvents).
///
/// Clients receive these server-pushed events:
///   • <c>alert:new</c>        — single alert ({alert json})
///   • <c>alert:batch</c>      — multiple alerts ({alerts: [...]})
///   • <c>presence:online</c>  — {userCount} — fired on every connect/disconnect
/// </summary>
[Authorize]
public sealed class AlertHub : Hub
{
    private static int _connectedCount;

    /// <summary>Event names kept in one place so server + tests can't drift from client.</summary>
    public static class Events
    {
        public const string AlertNew     = "alert:new";
        public const string AlertBatch   = "alert:batch";
        public const string Presence     = "presence:online";
    }

    public override async Task OnConnectedAsync()
    {
        Interlocked.Increment(ref _connectedCount);
        await base.OnConnectedAsync();
        await Clients.All.SendAsync(Events.Presence, new { userCount = _connectedCount });
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        Interlocked.Decrement(ref _connectedCount);
        await base.OnDisconnectedAsync(exception);
        await Clients.All.SendAsync(Events.Presence, new { userCount = _connectedCount });
    }

    /// <summary>Current online user count. Useful for tests.</summary>
    public static int ConnectedCount => _connectedCount;
}
