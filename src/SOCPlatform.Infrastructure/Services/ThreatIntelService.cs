using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// Enterprise-grade Threat Intelligence Service.
/// Manages IOC lifecycle, enrichment lookups, bulk feed import,
/// automated severity escalation, and statistics.
/// </summary>
public class ThreatIntelService
{
    private readonly SOCDbContext _db;
    private readonly ILogger<ThreatIntelService> _logger;

    public ThreatIntelService(SOCDbContext db, ILogger<ThreatIntelService> logger)
    {
        _db = db;
        _logger = logger;
    }

    // ──────────────── CRUD ────────────────

    public async Task<ThreatIntelIndicator> CreateAsync(CreateThreatIntelDto dto)
    {
        if (!Enum.TryParse<IndicatorType>(dto.IndicatorType, true, out var type))
            throw new ArgumentException($"Invalid indicator type: {dto.IndicatorType}");

        var existing = await _db.ThreatIntelIndicators.FirstOrDefaultAsync(
            i => i.IndicatorType == type && i.Value == dto.Value);

        if (existing != null)
        {
            // Update existing indicator with new data (merge strategy)
            existing.ConfidenceScore = Math.Max(existing.ConfidenceScore, dto.ConfidenceScore);
            existing.ThreatLevel = HigherThreatLevel(existing.ThreatLevel, dto.ThreatLevel);
            existing.ThreatType = string.IsNullOrEmpty(dto.ThreatType) ? existing.ThreatType : dto.ThreatType;
            existing.Source = MergeSources(existing.Source, dto.Source);
            existing.Description = dto.Description ?? existing.Description;
            existing.Tags = MergeTags(existing.Tags, dto.Tags);
            existing.AssociatedCVEs = MergeTags(existing.AssociatedCVEs, dto.AssociatedCVEs);
            existing.MitreTechniques = MergeTags(existing.MitreTechniques, dto.MitreTechniques);
            existing.GeoCountry = dto.GeoCountry ?? existing.GeoCountry;
            existing.ASN = dto.ASN ?? existing.ASN;
            existing.UpdatedAt = DateTime.UtcNow;
            existing.IsActive = true;
            if (dto.ExpiresAt.HasValue) existing.ExpiresAt = dto.ExpiresAt;

            await _db.SaveChangesAsync();
            _logger.LogInformation("Updated existing indicator {Value} (type={Type})", dto.Value, type);
            return existing;
        }

        var indicator = new ThreatIntelIndicator
        {
            Id = Guid.NewGuid(),
            IndicatorType = type,
            Value = dto.Value.Trim().ToLowerInvariant(),
            Source = dto.Source,
            ConfidenceScore = Math.Clamp(dto.ConfidenceScore, 0, 100),
            ThreatType = dto.ThreatType,
            ThreatLevel = dto.ThreatLevel,
            Description = dto.Description,
            Tags = dto.Tags,
            AssociatedCVEs = dto.AssociatedCVEs,
            MitreTechniques = dto.MitreTechniques,
            GeoCountry = dto.GeoCountry,
            ASN = dto.ASN,
            ExpiresAt = dto.ExpiresAt,
            FirstSeenAt = DateTime.UtcNow,
            CreatedAt = DateTime.UtcNow,
        };

        _db.ThreatIntelIndicators.Add(indicator);
        await _db.SaveChangesAsync();
        _logger.LogInformation("Created new indicator {Value} (type={Type}, threat={ThreatLevel})", indicator.Value, type, indicator.ThreatLevel);
        return indicator;
    }

    public async Task<BulkImportResult> BulkImportAsync(BulkImportDto dto)
    {
        var result = new BulkImportResult { FeedName = dto.FeedName };
        foreach (var item in dto.Indicators)
        {
            try
            {
                item.Source = string.IsNullOrEmpty(item.Source) ? dto.FeedName : item.Source;
                await CreateAsync(item);
                result.Imported++;
            }
            catch (Exception ex)
            {
                result.Failed++;
                result.Errors.Add($"{item.Value}: {ex.Message}");
            }
        }
        _logger.LogInformation("Bulk import from {Feed}: {Imported} imported, {Failed} failed",
            dto.FeedName, result.Imported, result.Failed);
        return result;
    }

    // ──────────────── Enrichment Engine ────────────────

    /// <summary>
    /// Enrich a value (IP, domain, hash, etc.) by looking it up against all active indicators.
    /// Increments hit count and updates last-matched timestamp on matches.
    /// </summary>
    public async Task<EnrichmentResultDto> EnrichAsync(string value, string? type = null)
    {
        var normalized = value.Trim().ToLowerInvariant();
        var query = _db.ThreatIntelIndicators
            .Where(i => i.IsActive && i.Value == normalized);

        if (type != null && Enum.TryParse<IndicatorType>(type, true, out var iType))
            query = query.Where(i => i.IndicatorType == iType);

        // Exclude expired
        query = query.Where(i => !i.ExpiresAt.HasValue || i.ExpiresAt > DateTime.UtcNow);

        var matches = await query.ToListAsync();

        // Update hit counts
        foreach (var match in matches)
        {
            match.HitCount++;
            match.LastMatchedAt = DateTime.UtcNow;
        }
        if (matches.Count > 0) await _db.SaveChangesAsync();

        return new EnrichmentResultDto
        {
            QueryValue = normalized,
            QueryType = type ?? "Auto",
            IsMalicious = matches.Count > 0,
            MatchCount = matches.Count,
            Matches = matches.Select(m => new ThreatIntelMatchDto
            {
                IndicatorId = m.Id,
                Source = m.Source,
                ThreatType = m.ThreatType,
                ThreatLevel = m.ThreatLevel,
                ConfidenceScore = m.ConfidenceScore,
                Tags = m.Tags,
                AssociatedCVEs = m.AssociatedCVEs,
                MitreTechniques = m.MitreTechniques,
                Description = m.Description,
            }).ToList(),
        };
    }

    /// <summary>
    /// Enrich a log entry's fields (source IP, destination IP, file hash, domain)
    /// and auto-escalate alert severity if critical threat intel matches are found.
    /// </summary>
    public async Task<List<EnrichmentResultDto>> EnrichLogFieldsAsync(
        string? sourceIp, string? destIp, string? fileHash, string? domain)
    {
        var results = new List<EnrichmentResultDto>();

        if (!string.IsNullOrEmpty(sourceIp))
            results.Add(await EnrichAsync(sourceIp, "IpAddress"));
        if (!string.IsNullOrEmpty(destIp))
            results.Add(await EnrichAsync(destIp, "IpAddress"));
        if (!string.IsNullOrEmpty(fileHash))
            results.Add(await EnrichAsync(fileHash, "FileHash"));
        if (!string.IsNullOrEmpty(domain))
            results.Add(await EnrichAsync(domain, "Domain"));

        return results.Where(r => r.MatchCount > 0).ToList();
    }

    /// <summary>
    /// Auto-escalate an alert's severity when it matches critical/high threat intel.
    /// Returns true if severity was escalated.
    /// </summary>
    public async Task<bool> AutoEscalateAlertAsync(Guid alertId)
    {
        var alert = await _db.Alerts.FindAsync(alertId);
        if (alert == null) return false;

        // Check source IP
        var enrichment = await EnrichAsync(alert.SourceIP ?? "", "IpAddress");
        if (!enrichment.IsMalicious) return false;

        var highestThreat = enrichment.Matches
            .OrderByDescending(m => ThreatLevelPriority(m.ThreatLevel))
            .FirstOrDefault();

        if (highestThreat == null) return false;

        var newSeverity = MapThreatLevelToSeverity(highestThreat.ThreatLevel);
        if (SeverityPriority(newSeverity) > SeverityPriority(alert.Severity))
        {
            var oldSeverity = alert.Severity;
            alert.Severity = newSeverity;
            alert.Description = $"{alert.Description}\n\n[THREAT INTEL] Auto-escalated from {oldSeverity} to {newSeverity}. " +
                                $"Source: {highestThreat.Source}, Type: {highestThreat.ThreatType}, " +
                                $"Confidence: {highestThreat.ConfidenceScore}%";
            await _db.SaveChangesAsync();
            _logger.LogWarning("Auto-escalated alert {AlertId} from {Old} to {New} based on threat intel",
                alertId, oldSeverity, newSeverity);
            return true;
        }
        return false;
    }

    // ──────────────── Statistics ────────────────

    public async Task<ThreatIntelStatsDto> GetStatsAsync()
    {
        var all = await _db.ThreatIntelIndicators.ToListAsync();
        var now = DateTime.UtcNow;

        return new ThreatIntelStatsDto
        {
            TotalIndicators = all.Count,
            ActiveIndicators = all.Count(i => i.IsActive && (!i.ExpiresAt.HasValue || i.ExpiresAt > now)),
            ExpiredIndicators = all.Count(i => i.ExpiresAt.HasValue && i.ExpiresAt <= now),
            TotalMatches = all.Sum(i => i.HitCount),
            MatchesLast24h = all.Count(i => i.LastMatchedAt.HasValue && i.LastMatchedAt >= now.AddHours(-24)),
            ByType = all.GroupBy(i => i.IndicatorType.ToString())
                        .ToDictionary(g => g.Key, g => g.Count()),
            ByThreatLevel = all.GroupBy(i => i.ThreatLevel)
                               .Where(g => !string.IsNullOrEmpty(g.Key))
                               .ToDictionary(g => g.Key, g => g.Count()),
            BySource = all.GroupBy(i => i.Source)
                          .Where(g => !string.IsNullOrEmpty(g.Key))
                          .ToDictionary(g => g.Key, g => g.Count()),
            ByThreatType = all.GroupBy(i => i.ThreatType)
                              .Where(g => !string.IsNullOrEmpty(g.Key))
                              .ToDictionary(g => g.Key, g => g.Count()),
            TopMatched = all.Where(i => i.HitCount > 0)
                            .OrderByDescending(i => i.HitCount)
                            .Take(10)
                            .Select(i => new TopIndicatorDto
                            {
                                Id = i.Id,
                                Value = i.Value,
                                IndicatorType = i.IndicatorType.ToString(),
                                ThreatLevel = i.ThreatLevel,
                                HitCount = i.HitCount,
                                LastMatchedAt = i.LastMatchedAt,
                            }).ToList(),
            RecentMatches = all.Where(i => i.LastMatchedAt.HasValue)
                               .OrderByDescending(i => i.LastMatchedAt)
                               .Take(10)
                               .Select(i => new RecentMatchDto
                               {
                                   IndicatorId = i.Id,
                                   Value = i.Value,
                                   IndicatorType = i.IndicatorType.ToString(),
                                   ThreatLevel = i.ThreatLevel,
                                   Source = i.Source,
                                   MatchedAt = i.LastMatchedAt!.Value,
                               }).ToList(),
        };
    }

    // ──────────────── Feed Seeding ────────────────

    /// <summary>
    /// Seeds demo threat intel data for development/testing.
    /// </summary>
    public async Task SeedDemoDataAsync()
    {
        if (await _db.ThreatIntelIndicators.AnyAsync()) return;

        var demoIndicators = new List<CreateThreatIntelDto>
        {
            new() { IndicatorType = "IpAddress", Value = "192.168.1.105", Source = "AbuseIPDB", ConfidenceScore = 95, ThreatType = "Botnet", ThreatLevel = "Critical", Description = "Known botnet C2 node", Tags = "botnet,c2,emotet", GeoCountry = "RU", ASN = "AS12345 Evil ISP" },
            new() { IndicatorType = "IpAddress", Value = "10.0.0.42", Source = "AlienVault OTX", ConfidenceScore = 78, ThreatType = "Scanner", ThreatLevel = "High", Description = "Persistent port scanner", Tags = "scanner,recon", GeoCountry = "CN", ASN = "AS67890 ChinaNet" },
            new() { IndicatorType = "IpAddress", Value = "172.16.5.99", Source = "VirusTotal", ConfidenceScore = 88, ThreatType = "APT", ThreatLevel = "Critical", Description = "APT28 infrastructure", Tags = "apt28,fancy_bear,state_sponsored", GeoCountry = "RU", MitreTechniques = "T1566,T1059,T1078" },
            new() { IndicatorType = "IpAddress", Value = "192.168.2.88", Source = "CrowdStrike", ConfidenceScore = 72, ThreatType = "Brute Force", ThreatLevel = "High", Description = "Credential stuffing source", Tags = "bruteforce,credentials" },
            new() { IndicatorType = "Domain", Value = "evil-c2-server.xyz", Source = "URLhaus", ConfidenceScore = 99, ThreatType = "C2", ThreatLevel = "Critical", Description = "Active C2 domain for LockBit ransomware", Tags = "c2,lockbit,ransomware", MitreTechniques = "T1071,T1573" },
            new() { IndicatorType = "Domain", Value = "phishing-bank-login.com", Source = "PhishTank", ConfidenceScore = 96, ThreatType = "Phishing", ThreatLevel = "High", Description = "Banking credential phishing page", Tags = "phishing,banking" },
            new() { IndicatorType = "Domain", Value = "malware-download.net", Source = "AlienVault OTX", ConfidenceScore = 91, ThreatType = "Malware Distribution", ThreatLevel = "Critical", Description = "Hosts multiple malware families", Tags = "malware,dropper,emotet" },
            new() { IndicatorType = "FileHash", Value = "e99a18c428cb38d5f260853678922e03", Source = "VirusTotal", ConfidenceScore = 100, ThreatType = "Ransomware", ThreatLevel = "Critical", Description = "LockBit 3.0 ransomware binary", Tags = "ransomware,lockbit,encryption", AssociatedCVEs = "CVE-2023-38831", MitreTechniques = "T1486,T1490" },
            new() { IndicatorType = "FileHash", Value = "5d41402abc4b2a76b9719d911017c592", Source = "Hybrid Analysis", ConfidenceScore = 85, ThreatType = "Trojan", ThreatLevel = "High", Description = "Remote access trojan (Cobalt Strike beacon)", Tags = "rat,cobaltstrike,beacon" },
            new() { IndicatorType = "FileHash", Value = "7d793037a0760186574b0282f2f435e7", Source = "YARA Rule Match", ConfidenceScore = 70, ThreatType = "Suspicious", ThreatLevel = "Medium", Description = "Packed PE binary with suspicious entropy", Tags = "packed,suspicious,pe" },
            new() { IndicatorType = "Url", Value = "http://evil-c2-server.xyz/beacon/config", Source = "URLhaus", ConfidenceScore = 98, ThreatType = "C2", ThreatLevel = "Critical", Description = "Cobalt Strike beacon configuration endpoint", Tags = "c2,cobaltstrike" },
            new() { IndicatorType = "Email", Value = "attacker@evil-c2-server.xyz", Source = "Manual", ConfidenceScore = 60, ThreatType = "Phishing", ThreatLevel = "Medium", Description = "Sender of spear-phishing campaign", Tags = "phishing,spearphish" },
            new() { IndicatorType = "IpAddress", Value = "185.220.101.42", Source = "Emerging Threats", ConfidenceScore = 82, ThreatType = "Tor Exit Node", ThreatLevel = "Medium", Description = "Known Tor exit node used for anonymization", Tags = "tor,anonymization", GeoCountry = "DE" },
            new() { IndicatorType = "IpAddress", Value = "45.33.32.156", Source = "Shodan", ConfidenceScore = 55, ThreatType = "Scanner", ThreatLevel = "Low", Description = "Shodan scanner IP", Tags = "scanner,shodan,benign", GeoCountry = "US" },
            new() { IndicatorType = "Domain", Value = "cryptominer-pool.ru", Source = "BlockList.de", ConfidenceScore = 90, ThreatType = "Cryptomining", ThreatLevel = "High", Description = "Cryptojacking mining pool", Tags = "crypto,mining,monero", GeoCountry = "RU" },
        };

        await BulkImportAsync(new BulkImportDto { FeedName = "SOC Demo Feed", Indicators = demoIndicators });
        _logger.LogInformation("Seeded {Count} demo threat intel indicators", demoIndicators.Count);
    }

    // ──────────────── Helpers ────────────────

    private static string MergeSources(string existing, string newSource)
    {
        if (string.IsNullOrEmpty(newSource)) return existing;
        var sources = existing.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet();
        sources.Add(newSource.Trim());
        return string.Join(", ", sources);
    }

    private static string? MergeTags(string? existing, string? newTags)
    {
        if (string.IsNullOrEmpty(newTags)) return existing;
        if (string.IsNullOrEmpty(existing)) return newTags;
        var tags = existing.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet();
        foreach (var t in newTags.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            tags.Add(t);
        return string.Join(",", tags);
    }

    private static string HigherThreatLevel(string a, string b) =>
        ThreatLevelPriority(a) >= ThreatLevelPriority(b) ? a : b;

    private static int ThreatLevelPriority(string level) => level?.ToLower() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "informational" => 0,
        _ => -1
    };

    private static Severity MapThreatLevelToSeverity(string threatLevel) => threatLevel?.ToLower() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        _ => Severity.Low,
    };

    private static int SeverityPriority(Severity severity) => severity switch
    {
        Severity.Critical => 4,
        Severity.High => 3,
        Severity.Medium => 2,
        Severity.Low => 1,
        _ => 0
    };
}

public class BulkImportResult
{
    public string FeedName { get; set; } = string.Empty;
    public int Imported { get; set; }
    public int Failed { get; set; }
    public List<string> Errors { get; set; } = new();
}
