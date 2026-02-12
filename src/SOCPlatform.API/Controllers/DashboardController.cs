using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Unified dashboard endpoints for analytics KPIs, trends, analyst performance, and MITRE coverage.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class DashboardController : ControllerBase
{
    private readonly SOCDbContext _context;

    public DashboardController(SOCDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Get operational KPIs: MTTD, MTTR, MTTC, false positive rate.
    /// </summary>
    [HttpGet("analytics")]
    public async Task<IActionResult> GetAnalytics()
    {
        var now = DateTime.UtcNow;
        var last30Days = now.AddDays(-30);
        var last7Days = now.AddDays(-7);

        var alerts = await _context.Alerts
            .Where(a => a.CreatedAt >= last30Days)
            .AsNoTracking()
            .ToListAsync();

        var resolvedAlerts = alerts.Where(a => a.ResolvedAt.HasValue).ToList();
        var acknowledgedAlerts = alerts.Where(a => a.AcknowledgedAt.HasValue).ToList();

        // MTTD — Mean Time to Detect (CreatedAt - event time, but since events trigger alerts automatically, use 0 or event delta if available)
        // For simplicity, MTTD = avg time from alert creation to acknowledgement (a proxy)
        double mttdMinutes = acknowledgedAlerts.Any()
            ? acknowledgedAlerts.Average(a => (a.AcknowledgedAt!.Value - a.CreatedAt).TotalMinutes)
            : 0;

        // MTTR — Mean Time to Respond (CreatedAt to ResolvedAt)
        double mttrMinutes = resolvedAlerts.Any()
            ? resolvedAlerts.Average(a => (a.ResolvedAt!.Value - a.CreatedAt).TotalMinutes)
            : 0;

        // MTTC — Mean Time to Close (CreatedAt to ClosedAt)
        var closedAlerts = alerts.Where(a => a.ClosedAt.HasValue).ToList();
        double mttcHours = closedAlerts.Any()
            ? closedAlerts.Average(a => (a.ClosedAt!.Value - a.CreatedAt).TotalHours)
            : 0;

        // False positive rate — resolved alerts that were likely false positives (Low severity + closed quickly)
        var fpCount = resolvedAlerts.Count(a =>
            a.Severity == Severity.Low &&
            a.ResolvedAt.HasValue &&
            (a.ResolvedAt.Value - a.CreatedAt).TotalMinutes < 10);
        double falsePositiveRate = alerts.Count > 0 ? Math.Round((double)fpCount / alerts.Count * 100, 1) : 0;

        // Weekly trend (last 7 days)
        var weeklyTrend = Enumerable.Range(0, 7)
            .Select(i =>
            {
                var day = now.AddDays(-6 + i).Date;
                var dayAlerts = alerts.Where(a => a.CreatedAt.Date == day).ToList();
                var dayResolved = dayAlerts.Count(a => a.ResolvedAt.HasValue);
                var dayMttr = dayAlerts
                    .Where(a => a.ResolvedAt.HasValue)
                    .Select(a => (a.ResolvedAt!.Value - a.CreatedAt).TotalMinutes)
                    .DefaultIfEmpty(0)
                    .Average();

                return new
                {
                    day = day.ToString("ddd"),
                    date = day.ToString("yyyy-MM-dd"),
                    alerts = dayAlerts.Count,
                    resolved = dayResolved,
                    mttr = Math.Round(dayMttr, 0)
                };
            })
            .ToList();

        // Analyst performance (last 7 days)
        var analystPerf = await _context.Alerts
            .Where(a => a.AssignedTo.HasValue && a.ResolvedAt.HasValue && a.ResolvedAt >= last7Days)
            .Include(a => a.AssignedAnalyst)
            .GroupBy(a => new { a.AssignedTo, Name = a.AssignedAnalyst!.Username })
            .Select(g => new
            {
                name = g.Key.Name,
                resolved = g.Count(),
                avgTimeMinutes = Math.Round(g.Average(a => (a.ResolvedAt!.Value - a.CreatedAt).TotalMinutes), 0),
                escalated = g.Count(a => a.Status == AlertStatus.Escalated)
            })
            .OrderByDescending(a => a.resolved)
            .ToListAsync();

        return Ok(ApiResponse<object>.Ok(new
        {
            kpis = new
            {
                mttd = FormatDuration(mttdMinutes),
                mttr = FormatDuration(mttrMinutes),
                mttc = FormatHours(mttcHours),
                falsePositiveRate = $"{falsePositiveRate}%",
                mttdRaw = Math.Round(mttdMinutes, 1),
                mttrRaw = Math.Round(mttrMinutes, 1),
                mttcRaw = Math.Round(mttcHours, 1),
                falsePositiveRateRaw = falsePositiveRate
            },
            weeklyTrend,
            analystPerformance = analystPerf
        }));
    }

    /// <summary>
    /// Get MITRE ATT&CK coverage from real alert data.
    /// </summary>
    [HttpGet("mitre")]
    public async Task<IActionResult> GetMitreCoverage()
    {
        var alerts = await _context.Alerts
            .Where(a => !string.IsNullOrEmpty(a.MitreTechnique))
            .AsNoTracking()
            .ToListAsync();

        // For each technique found in alerts, count hits
        var techniqueCounts = alerts
            .GroupBy(a => new { a.MitreTechnique, a.MitreTactic })
            .Select(g => new
            {
                techniqueId = g.Key.MitreTechnique,
                tactic = g.Key.MitreTactic ?? "Unknown",
                hits = g.Count()
            })
            .OrderByDescending(t => t.hits)
            .ToList();

        // Build a full MITRE matrix structure with real hit counts
        var tacticDefinitions = new[]
        {
            new { name = "Initial Access", techniques = new[] {
                new { id = "T1190", name = "Exploit Public App" },
                new { id = "T1078", name = "Valid Accounts" },
                new { id = "T1566", name = "Phishing" }
            }},
            new { name = "Execution", techniques = new[] {
                new { id = "T1204", name = "User Execution" },
                new { id = "T1059", name = "Command Script" },
                new { id = "T1053", name = "Scheduled Task" }
            }},
            new { name = "Persistence", techniques = new[] {
                new { id = "T1078", name = "Valid Accounts" },
                new { id = "T1136", name = "Create Account" },
                new { id = "T1053", name = "Scheduled Task" }
            }},
            new { name = "Privilege Escalation", techniques = new[] {
                new { id = "T1078", name = "Valid Accounts" },
                new { id = "T1548", name = "Abuse Elevation" },
                new { id = "T1134", name = "Token Manipulation" }
            }},
            new { name = "Defense Evasion", techniques = new[] {
                new { id = "T1078", name = "Valid Accounts" },
                new { id = "T1070", name = "Indicator Removal" },
                new { id = "T1036", name = "Masquerading" }
            }},
            new { name = "Credential Access", techniques = new[] {
                new { id = "T1110", name = "Brute Force" },
                new { id = "T1003", name = "OS Credential Dump" },
                new { id = "T1555", name = "Credentials Store" }
            }},
            new { name = "Discovery", techniques = new[] {
                new { id = "T1046", name = "Network Scan" },
                new { id = "T1087", name = "Account Discovery" },
                new { id = "T1082", name = "System Info" }
            }},
            new { name = "Lateral Movement", techniques = new[] {
                new { id = "T1021", name = "Remote Services" },
                new { id = "T1091", name = "Replication" }
            }},
            new { name = "Collection", techniques = new[] {
                new { id = "T1005", name = "Local Data" },
                new { id = "T1114", name = "Email Collection" }
            }},
            new { name = "Exfiltration", techniques = new[] {
                new { id = "T1041", name = "C2 Channel" },
                new { id = "T1048", name = "Alt Protocol" }
            }}
        };

        var matrix = tacticDefinitions.Select(tactic => new
        {
            tactic.name,
            techniques = tactic.techniques.Select(tech =>
            {
                var matchingAlerts = techniqueCounts.Where(t => t.techniqueId == tech.id).ToList();
                return new
                {
                    tech.id,
                    tech.name,
                    hits = matchingAlerts.Sum(m => m.hits)
                };
            })
        });

        var totalHits = techniqueCounts.Sum(t => t.hits);
        var activeTechniques = techniqueCounts.Select(t => t.techniqueId).Distinct().Count();

        return Ok(ApiResponse<object>.Ok(new
        {
            matrix,
            summary = new
            {
                totalHits,
                tacticsCount = tacticDefinitions.Length,
                activeTechniques
            }
        }));
    }

    /// <summary>
    /// Get 24-hour alert trend data for dashboard charts.
    /// </summary>
    [HttpGet("trend")]
    public async Task<IActionResult> GetAlertTrend()
    {
        var now = DateTime.UtcNow;
        var last24h = now.AddHours(-24);

        var alerts = await _context.Alerts
            .Where(a => a.CreatedAt >= last24h)
            .AsNoTracking()
            .ToListAsync();

        var trend = Enumerable.Range(0, 24)
            .Select(i =>
            {
                var hour = now.AddHours(-23 + i);
                var hourAlerts = alerts.Where(a => a.CreatedAt.Hour == hour.Hour && a.CreatedAt.Date == hour.Date).ToList();
                return new
                {
                    hour = hour.ToString("HH:00"),
                    alerts = hourAlerts.Count,
                    critical = hourAlerts.Count(a => a.Severity == Severity.Critical),
                    high = hourAlerts.Count(a => a.Severity == Severity.High)
                };
            })
            .ToList();

        return Ok(ApiResponse<object>.Ok(trend));
    }

    private static string FormatDuration(double minutes)
    {
        if (minutes < 1) return "<1m";
        if (minutes < 60) return $"{Math.Round(minutes, 0)}m";
        return $"{Math.Round(minutes / 60, 1)}h";
    }

    private static string FormatHours(double hours)
    {
        if (hours < 1) return $"{Math.Round(hours * 60, 0)}m";
        return $"{Math.Round(hours, 1)}h";
    }
}
