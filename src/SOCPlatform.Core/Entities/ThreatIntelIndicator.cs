using SOCPlatform.Core.Enums;

namespace SOCPlatform.Core.Entities;

/// <summary>
/// Enterprise-grade threat intelligence indicator.
/// Supports IPs, domains, file hashes, URLs, emails with enrichment metadata,
/// confidence scoring, threat classification, and feed provenance tracking.
/// </summary>
public class ThreatIntelIndicator
{
    public Guid Id { get; set; }
    public IndicatorType IndicatorType { get; set; }

    /// <summary>The indicator value (IP, domain, hash, URL, or email)</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>Feed or source name (e.g., "AbuseIPDB", "AlienVault OTX", "Manual")</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>Confidence score from the source feed (0–100)</summary>
    public int ConfidenceScore { get; set; }

    /// <summary>Threat classification: Malware, C2, Phishing, Botnet, Scanner, APT, etc.</summary>
    public string ThreatType { get; set; } = string.Empty;

    /// <summary>Priority level: Critical, High, Medium, Low, Informational</summary>
    public string ThreatLevel { get; set; } = string.Empty;

    /// <summary>Human-readable description of why this indicator is malicious</summary>
    public string? Description { get; set; }

    /// <summary>Comma-separated tags for categorization (e.g., "ransomware,lockbit,apt28")</summary>
    public string? Tags { get; set; }

    /// <summary>Associated CVE identifiers</summary>
    public string? AssociatedCVEs { get; set; }

    /// <summary>MITRE ATT&CK technique IDs (e.g., "T1566,T1059")</summary>
    public string? MitreTechniques { get; set; }

    /// <summary>Country of origin or geo info from feed</summary>
    public string? GeoCountry { get; set; }

    /// <summary>ASN information for IP indicators</summary>
    public string? ASN { get; set; }

    /// <summary>Number of times this indicator was matched against logs</summary>
    public int HitCount { get; set; }

    /// <summary>Last time this indicator matched a log entry</summary>
    public DateTime? LastMatchedAt { get; set; }

    /// <summary>Whether this indicator is actively used for matching</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>When the indicator was first seen in the feed</summary>
    public DateTime FirstSeenAt { get; set; } = DateTime.UtcNow;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    /// <summary>When this IOC expires (feed-dependent TTL)</summary>
    public DateTime? ExpiresAt { get; set; }
}
