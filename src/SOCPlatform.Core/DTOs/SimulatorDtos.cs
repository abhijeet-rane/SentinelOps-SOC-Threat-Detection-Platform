namespace SOCPlatform.Core.DTOs;

/// <summary>
/// Batch payload accepted by <c>POST /api/v1/simulator/inject</c>. Admin-only —
/// used by the AttackSim CLI and by red-team analysts to inject synthetic
/// SecurityEvents directly into the detection pipeline without needing to
/// replay full agent-side HMAC traffic.
/// </summary>
public sealed class SimulatorInjectRequest
{
    /// <summary>Free-text tag stored on every injected event so the tester can later filter their own data out.</summary>
    public string ScenarioTag { get; set; } = "manual";

    public List<SyntheticSecurityEventDto> Events { get; set; } = new();
}

public sealed class SyntheticSecurityEventDto
{
    public string EventCategory { get; set; } = string.Empty;
    public string EventAction { get; set; } = string.Empty;
    public string Severity { get; set; } = "Low";

    public string? SourceIP { get; set; }
    public string? DestinationIP { get; set; }
    public int?    DestinationPort { get; set; }

    public string? AffectedUser { get; set; }
    public string? AffectedDevice { get; set; }

    public string? FileHash { get; set; }
    public bool    IsThreatIntelMatch { get; set; }

    public string? MitreTechnique { get; set; }
    public string? MitreTactic { get; set; }

    /// <summary>JSON dict merged into SecurityEvent.Metadata (per-rule-specific fields go here).</summary>
    public Dictionary<string, object?>? Metadata { get; set; }

    /// <summary>Optional override — defaults to UtcNow at ingestion time.</summary>
    public DateTime? Timestamp { get; set; }
}

public sealed class SimulatorInjectResult
{
    public int    EventsInserted { get; set; }
    public long   FirstEventId   { get; set; }
    public long   LastEventId    { get; set; }
    public string ScenarioTag    { get; set; } = string.Empty;
    public DateTime InjectedAtUtc { get; set; }
}
