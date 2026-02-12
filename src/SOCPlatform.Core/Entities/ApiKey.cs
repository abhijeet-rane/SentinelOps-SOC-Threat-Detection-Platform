namespace SOCPlatform.Core.Entities;

/// <summary>
/// API key for endpoint agent authentication.
/// Uses HMAC-SHA256 with endpoint binding for secure agent → API communication.
/// </summary>
public class ApiKey
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string KeyHash { get; set; } = string.Empty;       // SHA-256 hash of the key
    public string? KeyPrefix { get; set; }                     // First 8 chars for identification
    public Guid? EndpointId { get; set; }                      // Bound to specific endpoint
    public string? AllowedEndpoints { get; set; }              // Comma-separated allowed endpoint paths
    public bool IsActive { get; set; } = true;
    public bool IsRevoked { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public Guid CreatedBy { get; set; }
}
