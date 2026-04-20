namespace SOCPlatform.Infrastructure.Configuration;

public sealed class ThreatIntelOptions
{
    public const string SectionName = "ThreatIntel";

    public AbuseIpDbOptions AbuseIpDb { get; init; } = new();
    public VirusTotalOptions VirusTotal { get; init; } = new();

    /// <summary>How long to cache enrichment lookups (seconds). Default 1 hour.</summary>
    public int CacheTtlSeconds { get; init; } = 3600;
}

public sealed class AbuseIpDbOptions
{
    public string ApiKey { get; init; } = string.Empty;
    public string BaseUrl { get; init; } = "https://api.abuseipdb.com/api/v2/";
    public int MaxConfidenceAge { get; init; } = 90;
}

public sealed class VirusTotalOptions
{
    public string ApiKey { get; init; } = string.Empty;
    public string BaseUrl { get; init; } = "https://www.virustotal.com/api/v3/";
}
