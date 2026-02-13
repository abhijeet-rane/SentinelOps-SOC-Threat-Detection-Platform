namespace SOCPlatform.Core.DTOs;

// ── Report Request ──

public class ReportRequestDto
{
    public DateTime? From { get; set; }
    public DateTime? To { get; set; }
    public string? Framework { get; set; } // ISO27001, SOC2, NIST
}

// ── Daily SOC Report ──

public class DailyReportDto
{
    public DateTime From { get; set; }
    public DateTime To { get; set; }
    public DailyKpis Kpis { get; set; } = new();
    public AlertBreakdown AlertBreakdown { get; set; } = new();
    public List<TopRuleHit> TopDetectionRules { get; set; } = new();
    public SlaComplianceDto SlaCompliance { get; set; } = new();
    public int TotalLogsIngested { get; set; }
    public int PlaybookExecutions { get; set; }
    public int NewIncidents { get; set; }
}

public class DailyKpis
{
    public int TotalAlerts { get; set; }
    public int ResolvedAlerts { get; set; }
    public int EscalatedAlerts { get; set; }
    public double MttdMinutes { get; set; }
    public double MttrMinutes { get; set; }
    public double FalsePositiveRate { get; set; }
}

public class AlertBreakdown
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int New { get; set; }
    public int InProgress { get; set; }
    public int Escalated { get; set; }
    public int Resolved { get; set; }
    public int Closed { get; set; }
}

public class TopRuleHit
{
    public string RuleName { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string? MitreTechnique { get; set; }
    public int Hits { get; set; }
}

public class SlaComplianceDto
{
    public int TotalWithSla { get; set; }
    public int WithinSla { get; set; }
    public int Breached { get; set; }
    public double CompliancePercent { get; set; }
}

// ── Incident Summary Report ──

public class IncidentSummaryReportDto
{
    public DateTime From { get; set; }
    public DateTime To { get; set; }
    public int TotalIncidents { get; set; }
    public int OpenIncidents { get; set; }
    public int ResolvedIncidents { get; set; }
    public int ClosedIncidents { get; set; }
    public double AvgResolutionHours { get; set; }
    public IncidentSeverityBreakdown SeverityBreakdown { get; set; } = new();
    public List<IncidentSummaryItem> Incidents { get; set; } = new();
}

public class IncidentSeverityBreakdown
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
}

public class IncidentSummaryItem
{
    public Guid Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? RootCause { get; set; }
    public int AlertCount { get; set; }
    public double? ResolutionHours { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
}

// ── Analyst Performance Report ──

public class AnalystPerformanceReportDto
{
    public DateTime From { get; set; }
    public DateTime To { get; set; }
    public List<AnalystMetrics> Analysts { get; set; } = new();
}

public class AnalystMetrics
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public int AssignedAlerts { get; set; }
    public int ResolvedAlerts { get; set; }
    public int EscalatedAlerts { get; set; }
    public double AvgResolutionMinutes { get; set; }
    public double SlaCompliancePercent { get; set; }
    public int IncidentsWorked { get; set; }
}

// ── Compliance Report ──

public class ComplianceReportDto
{
    public DateTime From { get; set; }
    public DateTime To { get; set; }
    public string Framework { get; set; } = string.Empty;
    public string FrameworkVersion { get; set; } = string.Empty;
    public double OverallScore { get; set; }
    public List<ComplianceControlDto> Controls { get; set; } = new();
}

public class ComplianceControlDto
{
    public string ControlId { get; set; } = string.Empty;
    public string ControlName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty; // Compliant, Partial, NonCompliant
    public string Evidence { get; set; } = string.Empty;
    public string? Notes { get; set; }
}
