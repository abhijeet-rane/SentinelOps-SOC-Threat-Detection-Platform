namespace SOCPlatform.Core.DTOs;

/// <summary>
/// Dashboard overview data for the SOC main screen.
/// </summary>
public class DashboardDto
{
    public int TotalAlerts { get; set; }
    public int NewAlerts { get; set; }
    public int InProgressAlerts { get; set; }
    public int CriticalAlerts { get; set; }
    public int ActiveIncidents { get; set; }
    public int TotalLogsToday { get; set; }
    public double MeanTimeToAcknowledge { get; set; }   // minutes
    public double MeanTimeToResolve { get; set; }       // minutes
    public List<SeverityCountDto> AlertsBySeverity { get; set; } = new();
    public List<TimeSeriesDataPoint> AlertTrend { get; set; } = new();
    public List<TopAttackerDto> TopAttackingIPs { get; set; } = new();
    public List<MitreTechniqueDto> MitreTechniques { get; set; } = new();
}

public class SeverityCountDto
{
    public string Severity { get; set; } = string.Empty;
    public int Count { get; set; }
}

public class TimeSeriesDataPoint
{
    public DateTime Timestamp { get; set; }
    public int Value { get; set; }
}

public class TopAttackerDto
{
    public string IpAddress { get; set; } = string.Empty;
    public int AlertCount { get; set; }
    public string? Country { get; set; }
    public string? City { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
}

public class MitreTechniqueDto
{
    public string TechniqueId { get; set; } = string.Empty;
    public string TechniqueName { get; set; } = string.Empty;
    public string Tactic { get; set; } = string.Empty;
    public int Count { get; set; }
}
