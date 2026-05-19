using System.Text.Json.Serialization;

namespace SOCPlatform.DesktopAgent.Models;

public class AgentConfig
{
    [JsonPropertyName("apiBaseUrl")]
    public string ApiBaseUrl { get; set; } = "http://localhost:5101";

    [JsonPropertyName("apiKey")]
    public string ApiKey { get; set; } = "test-api-key-for-soc-platform-2026";

    [JsonPropertyName("endpointId")]
    public Guid EndpointId { get; set; } = Guid.NewGuid();

    [JsonPropertyName("collectionIntervalSeconds")]
    public int CollectionIntervalSeconds { get; set; } = 30;

    [JsonPropertyName("pinnedThumbprintSha256")]
    public string? PinnedThumbprintSha256 { get; set; }

    [JsonPropertyName("allowInvalidCerts")]
    public bool AllowInvalidCerts { get; set; } = true;
}
