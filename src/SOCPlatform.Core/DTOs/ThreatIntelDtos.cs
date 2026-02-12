namespace SOCPlatform.Core.DTOs;

/// <summary>
/// DTO for creating/importing threat intelligence indicators.
/// </summary>
public class CreateThreatIntelDto
{
    public string IndicatorType { get; set; } = string.Empty; // IpAddress, Domain, FileHash, Url, Email
    public string Value { get; set; } = string.Empty;
    public string Source { get; set; } = "Manual";
    public int ConfidenceScore { get; set; } = 50;
    public string ThreatType { get; set; } = string.Empty;
    public string ThreatLevel { get; set; } = "Medium";
    public string? Description { get; set; }
    public string? Tags { get; set; }
    public string? AssociatedCVEs { get; set; }
    public string? MitreTechniques { get; set; }
    public string? GeoCountry { get; set; }
    public string? ASN { get; set; }
    public DateTime? ExpiresAt { get; set; }
}

/// <summary>
/// DTO for bulk importing indicators from a CSV/STIX feed.
/// </summary>
public class BulkImportDto
{
    public List<CreateThreatIntelDto> Indicators { get; set; } = new();
    public string FeedName { get; set; } = string.Empty;
}

/// <summary>
/// Response DTO for threat intel indicators.
/// </summary>
public class ThreatIntelDto
{
    public Guid Id { get; set; }
    public string IndicatorType { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public int ConfidenceScore { get; set; }
    public string ThreatType { get; set; } = string.Empty;
    public string ThreatLevel { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? Tags { get; set; }
    public string? AssociatedCVEs { get; set; }
    public string? MitreTechniques { get; set; }
    public string? GeoCountry { get; set; }
    public string? ASN { get; set; }
    public int HitCount { get; set; }
    public DateTime? LastMatchedAt { get; set; }
    public bool IsActive { get; set; }
    public DateTime FirstSeenAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value < DateTime.UtcNow;
}

/// <summary>
/// Filter/search DTO for threat intel indicators.
/// </summary>
public class ThreatIntelFilterDto
{
    public string? IndicatorType { get; set; }
    public string? ThreatLevel { get; set; }
    public string? ThreatType { get; set; }
    public string? Source { get; set; }
    public string? SearchValue { get; set; }
    public string? Tag { get; set; }
    public bool? IsActive { get; set; }
    public bool? HasMatches { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 25;
    public string SortBy { get; set; } = "CreatedAt";
    public string SortOrder { get; set; } = "desc";
}

/// <summary>
/// Result of enriching a value (IP/domain/hash) against threat intel.
/// </summary>
public class EnrichmentResultDto
{
    public string QueryValue { get; set; } = string.Empty;
    public string QueryType { get; set; } = string.Empty;
    public bool IsMalicious { get; set; }
    public int MatchCount { get; set; }
    public List<ThreatIntelMatchDto> Matches { get; set; } = new();
}

/// <summary>
/// Individual match from enrichment.
/// </summary>
public class ThreatIntelMatchDto
{
    public Guid IndicatorId { get; set; }
    public string Source { get; set; } = string.Empty;
    public string ThreatType { get; set; } = string.Empty;
    public string ThreatLevel { get; set; } = string.Empty;
    public int ConfidenceScore { get; set; }
    public string? Tags { get; set; }
    public string? AssociatedCVEs { get; set; }
    public string? MitreTechniques { get; set; }
    public string? Description { get; set; }
}

/// <summary>
/// Dashboard stats for threat intel overview.
/// </summary>
public class ThreatIntelStatsDto
{
    public int TotalIndicators { get; set; }
    public int ActiveIndicators { get; set; }
    public int ExpiredIndicators { get; set; }
    public int TotalMatches { get; set; }
    public int MatchesLast24h { get; set; }
    public Dictionary<string, int> ByType { get; set; } = new();
    public Dictionary<string, int> ByThreatLevel { get; set; } = new();
    public Dictionary<string, int> BySource { get; set; } = new();
    public Dictionary<string, int> ByThreatType { get; set; } = new();
    public List<TopIndicatorDto> TopMatched { get; set; } = new();
    public List<RecentMatchDto> RecentMatches { get; set; } = new();
}

public class TopIndicatorDto
{
    public Guid Id { get; set; }
    public string Value { get; set; } = string.Empty;
    public string IndicatorType { get; set; } = string.Empty;
    public string ThreatLevel { get; set; } = string.Empty;
    public int HitCount { get; set; }
    public DateTime? LastMatchedAt { get; set; }
}

public class RecentMatchDto
{
    public Guid IndicatorId { get; set; }
    public string Value { get; set; } = string.Empty;
    public string IndicatorType { get; set; } = string.Empty;
    public string ThreatLevel { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public DateTime MatchedAt { get; set; }
}
