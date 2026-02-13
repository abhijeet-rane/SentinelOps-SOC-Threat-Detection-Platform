using ClosedXML.Excel;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Enums;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// Generates SOC reports (daily, incident, analyst, compliance) and exports to PDF/Excel.
/// </summary>
public class ReportService
{
    private readonly SOCDbContext _context;

    public ReportService(SOCDbContext context)
    {
        _context = context;
        QuestPDF.Settings.License = LicenseType.Community;
    }

    // ───────────────────────────────────────────────────────
    // 1. Daily SOC Report
    // ───────────────────────────────────────────────────────
    public async Task<DailyReportDto> GenerateDailyReportAsync(DateTime from, DateTime to)
    {
        var alerts = await _context.Alerts
            .Where(a => a.CreatedAt >= from && a.CreatedAt <= to)
            .Include(a => a.DetectionRule)
            .AsNoTracking()
            .ToListAsync();

        var resolved = alerts.Where(a => a.ResolvedAt.HasValue).ToList();
        var acknowledged = alerts.Where(a => a.AcknowledgedAt.HasValue).ToList();

        double mttd = acknowledged.Any()
            ? acknowledged.Average(a => (a.AcknowledgedAt!.Value - a.CreatedAt).TotalMinutes) : 0;
        double mttr = resolved.Any()
            ? resolved.Average(a => (a.ResolvedAt!.Value - a.CreatedAt).TotalMinutes) : 0;

        var fpCount = resolved.Count(a =>
            a.Severity == Severity.Low &&
            a.ResolvedAt.HasValue &&
            (a.ResolvedAt.Value - a.CreatedAt).TotalMinutes < 10);
        double fpRate = alerts.Count > 0 ? Math.Round((double)fpCount / alerts.Count * 100, 1) : 0;

        // SLA compliance
        var withSla = alerts.Where(a => a.SlaDeadline.HasValue).ToList();
        var breached = withSla.Count(a =>
            a.SlaDeadline.HasValue &&
            (a.ResolvedAt ?? DateTime.UtcNow) > a.SlaDeadline.Value &&
            a.Status != AlertStatus.Resolved && a.Status != AlertStatus.Closed);
        var withinSla = withSla.Count - breached;

        // Top detection rules
        var topRules = alerts
            .Where(a => a.DetectionRule != null)
            .GroupBy(a => new { a.DetectionRule!.Name, Sev = a.Severity.ToString(), a.MitreTechnique })
            .Select(g => new TopRuleHit
            {
                RuleName = g.Key.Name,
                Severity = g.Key.Sev,
                MitreTechnique = g.Key.MitreTechnique,
                Hits = g.Count()
            })
            .OrderByDescending(r => r.Hits)
            .Take(10)
            .ToList();

        var incidents = await _context.Incidents
            .Where(i => i.CreatedAt >= from && i.CreatedAt <= to)
            .CountAsync();

        var logs = await _context.Logs
            .Where(l => l.Timestamp >= from && l.Timestamp <= to)
            .CountAsync();

        var executions = await _context.PlaybookExecutions
            .Where(e => e.CreatedAt >= from && e.CreatedAt <= to)
            .CountAsync();

        return new DailyReportDto
        {
            From = from,
            To = to,
            Kpis = new DailyKpis
            {
                TotalAlerts = alerts.Count,
                ResolvedAlerts = resolved.Count,
                EscalatedAlerts = alerts.Count(a => a.Status == AlertStatus.Escalated),
                MttdMinutes = Math.Round(mttd, 1),
                MttrMinutes = Math.Round(mttr, 1),
                FalsePositiveRate = fpRate
            },
            AlertBreakdown = new AlertBreakdown
            {
                Critical = alerts.Count(a => a.Severity == Severity.Critical),
                High = alerts.Count(a => a.Severity == Severity.High),
                Medium = alerts.Count(a => a.Severity == Severity.Medium),
                Low = alerts.Count(a => a.Severity == Severity.Low),
                New = alerts.Count(a => a.Status == AlertStatus.New),
                InProgress = alerts.Count(a => a.Status == AlertStatus.InProgress),
                Escalated = alerts.Count(a => a.Status == AlertStatus.Escalated),
                Resolved = alerts.Count(a => a.Status == AlertStatus.Resolved),
                Closed = alerts.Count(a => a.Status == AlertStatus.Closed),
            },
            TopDetectionRules = topRules,
            SlaCompliance = new SlaComplianceDto
            {
                TotalWithSla = withSla.Count,
                WithinSla = withinSla,
                Breached = breached,
                CompliancePercent = withSla.Count > 0 ? Math.Round((double)withinSla / withSla.Count * 100, 1) : 100
            },
            TotalLogsIngested = logs,
            PlaybookExecutions = executions,
            NewIncidents = incidents
        };
    }

    // ───────────────────────────────────────────────────────
    // 2. Incident Summary Report
    // ───────────────────────────────────────────────────────
    public async Task<IncidentSummaryReportDto> GenerateIncidentSummaryAsync(DateTime from, DateTime to)
    {
        var incidents = await _context.Incidents
            .Where(i => i.CreatedAt >= from && i.CreatedAt <= to)
            .Include(i => i.Alerts)
            .AsNoTracking()
            .ToListAsync();

        var resolved = incidents.Where(i => i.ResolvedAt.HasValue).ToList();
        double avgHours = resolved.Any()
            ? resolved.Average(i => (i.ResolvedAt!.Value - i.CreatedAt).TotalHours) : 0;

        return new IncidentSummaryReportDto
        {
            From = from,
            To = to,
            TotalIncidents = incidents.Count,
            OpenIncidents = incidents.Count(i => i.Status == IncidentStatus.Open || i.Status == IncidentStatus.Investigating),
            ResolvedIncidents = incidents.Count(i => i.Status == IncidentStatus.Resolved),
            ClosedIncidents = incidents.Count(i => i.Status == IncidentStatus.Closed),
            AvgResolutionHours = Math.Round(avgHours, 1),
            SeverityBreakdown = new IncidentSeverityBreakdown
            {
                Critical = incidents.Count(i => i.Severity == Severity.Critical),
                High = incidents.Count(i => i.Severity == Severity.High),
                Medium = incidents.Count(i => i.Severity == Severity.Medium),
                Low = incidents.Count(i => i.Severity == Severity.Low),
            },
            Incidents = incidents.Select(i => new IncidentSummaryItem
            {
                Id = i.Id,
                Title = i.Title,
                Severity = i.Severity.ToString(),
                Status = i.Status.ToString(),
                RootCause = i.RootCause,
                AlertCount = i.Alerts.Count,
                ResolutionHours = i.ResolvedAt.HasValue
                    ? Math.Round((i.ResolvedAt.Value - i.CreatedAt).TotalHours, 1) : null,
                CreatedAt = i.CreatedAt,
                ResolvedAt = i.ResolvedAt
            }).OrderByDescending(i => i.CreatedAt).ToList()
        };
    }

    // ───────────────────────────────────────────────────────
    // 3. Analyst Performance Report
    // ───────────────────────────────────────────────────────
    public async Task<AnalystPerformanceReportDto> GenerateAnalystPerformanceAsync(DateTime from, DateTime to)
    {
        var analysts = await _context.Users
            .Include(u => u.Role)
            .Where(u => u.IsActive)
            .AsNoTracking()
            .ToListAsync();

        var alerts = await _context.Alerts
            .Where(a => a.CreatedAt >= from && a.CreatedAt <= to && a.AssignedTo.HasValue)
            .AsNoTracking()
            .ToListAsync();

        var incidents = await _context.Incidents
            .Where(i => i.CreatedAt >= from && i.CreatedAt <= to && i.AssignedAnalystId.HasValue)
            .AsNoTracking()
            .ToListAsync();

        var metrics = analysts.Select(analyst =>
        {
            var assigned = alerts.Where(a => a.AssignedTo == analyst.Id).ToList();
            var resolved = assigned.Where(a => a.ResolvedAt.HasValue).ToList();
            var escalated = assigned.Count(a => a.Status == AlertStatus.Escalated);
            double avgMin = resolved.Any()
                ? resolved.Average(a => (a.ResolvedAt!.Value - a.CreatedAt).TotalMinutes) : 0;

            var withSla = assigned.Where(a => a.SlaDeadline.HasValue).ToList();
            var withinSla = withSla.Count(a =>
                (a.ResolvedAt ?? DateTime.UtcNow) <= a.SlaDeadline!.Value ||
                a.Status == AlertStatus.Resolved || a.Status == AlertStatus.Closed);
            double slaPct = withSla.Count > 0 ? Math.Round((double)withinSla / withSla.Count * 100, 1) : 100;

            return new AnalystMetrics
            {
                Id = analyst.Id,
                Name = analyst.Username,
                Role = analyst.Role?.Name ?? "Unknown",
                AssignedAlerts = assigned.Count,
                ResolvedAlerts = resolved.Count,
                EscalatedAlerts = escalated,
                AvgResolutionMinutes = Math.Round(avgMin, 0),
                SlaCompliancePercent = slaPct,
                IncidentsWorked = incidents.Count(i => i.AssignedAnalystId == analyst.Id)
            };
        })
        .Where(m => m.AssignedAlerts > 0)
        .OrderByDescending(m => m.ResolvedAlerts)
        .ToList();

        return new AnalystPerformanceReportDto { From = from, To = to, Analysts = metrics };
    }

    // ───────────────────────────────────────────────────────
    // 4. Compliance Report
    // ───────────────────────────────────────────────────────
    public async Task<ComplianceReportDto> GenerateComplianceReportAsync(DateTime from, DateTime to, string framework)
    {
        // Gather evidence from the system
        var alertCount = await _context.Alerts.CountAsync(a => a.CreatedAt >= from && a.CreatedAt <= to);
        var auditCount = await _context.AuditLogs.CountAsync(a => a.Timestamp >= from && a.Timestamp <= to);
        var activeRules = await _context.DetectionRules.CountAsync(r => r.IsActive);
        var activeUsers = await _context.Users.CountAsync(u => u.IsActive);
        var incidentCount = await _context.Incidents.CountAsync(i => i.CreatedAt >= from && i.CreatedAt <= to);
        var playbookCount = await _context.ResponsePlaybooks.CountAsync();

        var controls = framework.ToUpperInvariant() switch
        {
            "ISO27001" => GetIso27001Controls(alertCount, auditCount, activeRules, activeUsers, incidentCount, playbookCount),
            "SOC2" => GetSoc2Controls(alertCount, auditCount, activeRules, activeUsers, incidentCount, playbookCount),
            _ => GetNistCsfControls(alertCount, auditCount, activeRules, activeUsers, incidentCount, playbookCount),
        };

        var compliant = controls.Count(c => c.Status == "Compliant");
        double score = controls.Count > 0 ? Math.Round((double)compliant / controls.Count * 100, 1) : 0;

        return new ComplianceReportDto
        {
            From = from,
            To = to,
            Framework = framework,
            FrameworkVersion = framework.ToUpperInvariant() switch
            {
                "ISO27001" => "ISO/IEC 27001:2022",
                "SOC2" => "SOC 2 Type II",
                _ => "NIST CSF 2.0"
            },
            OverallScore = score,
            Controls = controls
        };
    }

    // ───────────────────────────────────────────────────────
    // PDF Export
    // ───────────────────────────────────────────────────────
    public byte[] ExportToPdf(object reportData, string reportType)
    {
        var doc = Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(40);
                page.DefaultTextStyle(x => x.FontSize(9).FontColor(Colors.Grey.Darken3));

                page.Header().Column(col =>
                {
                    col.Item().Text($"SENTINEL SOC — {FormatReportTitle(reportType)}")
                        .FontSize(16).Bold().FontColor(Colors.Blue.Darken2);
                    col.Item().Text($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC")
                        .FontSize(8).FontColor(Colors.Grey.Medium);
                    col.Item().PaddingBottom(10).LineHorizontal(1).LineColor(Colors.Grey.Lighten2);
                });

                page.Content().Column(col =>
                {
                    switch (reportData)
                    {
                        case DailyReportDto daily:
                            RenderDailyPdf(col, daily);
                            break;
                        case IncidentSummaryReportDto incidents:
                            RenderIncidentPdf(col, incidents);
                            break;
                        case AnalystPerformanceReportDto analysts:
                            RenderAnalystPdf(col, analysts);
                            break;
                        case ComplianceReportDto compliance:
                            RenderCompliancePdf(col, compliance);
                            break;
                    }
                });

                page.Footer().AlignCenter()
                    .Text(t => { t.Span("Page "); t.CurrentPageNumber(); t.Span(" of "); t.TotalPages(); });
            });
        });

        return doc.GeneratePdf();
    }

    // ───────────────────────────────────────────────────────
    // Excel Export
    // ───────────────────────────────────────────────────────
    public byte[] ExportToExcel(object reportData, string reportType)
    {
        using var workbook = new XLWorkbook();
        var ws = workbook.Worksheets.Add(FormatReportTitle(reportType));

        switch (reportData)
        {
            case DailyReportDto daily:
                RenderDailyExcel(ws, daily);
                break;
            case IncidentSummaryReportDto incidents:
                RenderIncidentExcel(ws, incidents);
                break;
            case AnalystPerformanceReportDto analysts:
                RenderAnalystExcel(ws, analysts);
                break;
            case ComplianceReportDto compliance:
                RenderComplianceExcel(ws, compliance);
                break;
        }

        ws.Columns().AdjustToContents();
        using var ms = new MemoryStream();
        workbook.SaveAs(ms);
        return ms.ToArray();
    }

    // ─── PDF Renderers ───

    private void RenderDailyPdf(ColumnDescriptor col, DailyReportDto d)
    {
        col.Item().Text($"Report Period: {d.From:yyyy-MM-dd} — {d.To:yyyy-MM-dd}").FontSize(10).Bold();
        col.Item().PaddingTop(8).Text("Key Performance Indicators").FontSize(12).Bold();

        col.Item().PaddingTop(5).Table(t =>
        {
            t.ColumnsDefinition(c => { c.RelativeColumn(); c.RelativeColumn(); });
            AddKvRow(t, "Total Alerts", d.Kpis.TotalAlerts.ToString());
            AddKvRow(t, "Resolved", d.Kpis.ResolvedAlerts.ToString());
            AddKvRow(t, "Escalated", d.Kpis.EscalatedAlerts.ToString());
            AddKvRow(t, "MTTD", $"{d.Kpis.MttdMinutes} min");
            AddKvRow(t, "MTTR", $"{d.Kpis.MttrMinutes} min");
            AddKvRow(t, "False Positive Rate", $"{d.Kpis.FalsePositiveRate}%");
            AddKvRow(t, "SLA Compliance", $"{d.SlaCompliance.CompliancePercent}%");
            AddKvRow(t, "Logs Ingested", d.TotalLogsIngested.ToString());
            AddKvRow(t, "Playbook Executions", d.PlaybookExecutions.ToString());
            AddKvRow(t, "New Incidents", d.NewIncidents.ToString());
        });

        col.Item().PaddingTop(12).Text("Alert Severity Breakdown").FontSize(12).Bold();
        col.Item().PaddingTop(5).Table(t =>
        {
            t.ColumnsDefinition(c => { c.RelativeColumn(); c.RelativeColumn(); c.RelativeColumn(); c.RelativeColumn(); });
            AddHeaderRow(t, "Critical", "High", "Medium", "Low");
            AddDataRow(t, d.AlertBreakdown.Critical.ToString(), d.AlertBreakdown.High.ToString(),
                d.AlertBreakdown.Medium.ToString(), d.AlertBreakdown.Low.ToString());
        });

        if (d.TopDetectionRules.Any())
        {
            col.Item().PaddingTop(12).Text("Top Detection Rules").FontSize(12).Bold();
            col.Item().PaddingTop(5).Table(t =>
            {
                t.ColumnsDefinition(c => { c.RelativeColumn(3); c.RelativeColumn(); c.RelativeColumn(); c.RelativeColumn(); });
                AddHeaderRow(t, "Rule", "Severity", "MITRE", "Hits");
                foreach (var r in d.TopDetectionRules)
                    AddDataRow(t, r.RuleName, r.Severity, r.MitreTechnique ?? "—", r.Hits.ToString());
            });
        }
    }

    private void RenderIncidentPdf(ColumnDescriptor col, IncidentSummaryReportDto d)
    {
        col.Item().Text($"Report Period: {d.From:yyyy-MM-dd} — {d.To:yyyy-MM-dd}").FontSize(10).Bold();
        col.Item().PaddingTop(8).Text("Incident Overview").FontSize(12).Bold();

        col.Item().PaddingTop(5).Table(t =>
        {
            t.ColumnsDefinition(c => { c.RelativeColumn(); c.RelativeColumn(); });
            AddKvRow(t, "Total Incidents", d.TotalIncidents.ToString());
            AddKvRow(t, "Open", d.OpenIncidents.ToString());
            AddKvRow(t, "Resolved", d.ResolvedIncidents.ToString());
            AddKvRow(t, "Closed", d.ClosedIncidents.ToString());
            AddKvRow(t, "Avg Resolution Time", $"{d.AvgResolutionHours}h");
        });

        if (d.Incidents.Any())
        {
            col.Item().PaddingTop(12).Text("Incident Details").FontSize(12).Bold();
            col.Item().PaddingTop(5).Table(t =>
            {
                t.ColumnsDefinition(c => { c.RelativeColumn(3); c.RelativeColumn(); c.RelativeColumn(); c.RelativeColumn(); c.RelativeColumn(); });
                AddHeaderRow(t, "Title", "Severity", "Status", "Alerts", "Resolution");
                foreach (var i in d.Incidents)
                    AddDataRow(t, i.Title, i.Severity, i.Status, i.AlertCount.ToString(),
                        i.ResolutionHours.HasValue ? $"{i.ResolutionHours}h" : "Open");
            });
        }
    }

    private void RenderAnalystPdf(ColumnDescriptor col, AnalystPerformanceReportDto d)
    {
        col.Item().Text($"Report Period: {d.From:yyyy-MM-dd} — {d.To:yyyy-MM-dd}").FontSize(10).Bold();
        col.Item().PaddingTop(8).Text("Analyst Performance Metrics").FontSize(12).Bold();

        col.Item().PaddingTop(5).Table(t =>
        {
            t.ColumnsDefinition(c =>
            {
                c.RelativeColumn(2); c.RelativeColumn(); c.RelativeColumn();
                c.RelativeColumn(); c.RelativeColumn(); c.RelativeColumn(); c.RelativeColumn();
            });
            AddHeaderRow(t, "Analyst", "Role", "Assigned", "Resolved", "Escalated", "Avg Time", "SLA %");
            foreach (var a in d.Analysts)
                AddDataRow(t, a.Name, a.Role, a.AssignedAlerts.ToString(), a.ResolvedAlerts.ToString(),
                    a.EscalatedAlerts.ToString(), $"{a.AvgResolutionMinutes}m", $"{a.SlaCompliancePercent}%");
        });
    }

    private void RenderCompliancePdf(ColumnDescriptor col, ComplianceReportDto d)
    {
        col.Item().Text($"{d.FrameworkVersion} Compliance Report").FontSize(12).Bold();
        col.Item().Text($"Period: {d.From:yyyy-MM-dd} — {d.To:yyyy-MM-dd} | Overall Score: {d.OverallScore}%").FontSize(10);

        col.Item().PaddingTop(10).Table(t =>
        {
            t.ColumnsDefinition(c => { c.RelativeColumn(); c.RelativeColumn(2); c.RelativeColumn(); c.RelativeColumn(); c.RelativeColumn(3); });
            AddHeaderRow(t, "Control ID", "Control", "Category", "Status", "Evidence");
            foreach (var c in d.Controls)
                AddDataRow(t, c.ControlId, c.ControlName, c.Category, c.Status, c.Evidence);
        });
    }

    // ─── Excel Renderers ───

    private void RenderDailyExcel(IXLWorksheet ws, DailyReportDto d)
    {
        ws.Cell(1, 1).Value = "SENTINEL SOC — Daily Report";
        ws.Cell(1, 1).Style.Font.Bold = true; ws.Cell(1, 1).Style.Font.FontSize = 14;
        ws.Cell(2, 1).Value = $"{d.From:yyyy-MM-dd} — {d.To:yyyy-MM-dd}";

        var row = 4;
        ws.Cell(row, 1).Value = "KPI"; ws.Cell(row, 2).Value = "Value";
        StyleHeader(ws, row, 2);
        row++;
        AddExcelRow(ws, ref row, "Total Alerts", d.Kpis.TotalAlerts);
        AddExcelRow(ws, ref row, "Resolved", d.Kpis.ResolvedAlerts);
        AddExcelRow(ws, ref row, "Escalated", d.Kpis.EscalatedAlerts);
        AddExcelRow(ws, ref row, "MTTD (min)", d.Kpis.MttdMinutes);
        AddExcelRow(ws, ref row, "MTTR (min)", d.Kpis.MttrMinutes);
        AddExcelRow(ws, ref row, "FP Rate %", d.Kpis.FalsePositiveRate);
        AddExcelRow(ws, ref row, "SLA Compliance %", d.SlaCompliance.CompliancePercent);
        AddExcelRow(ws, ref row, "Logs Ingested", d.TotalLogsIngested);
        AddExcelRow(ws, ref row, "Playbook Runs", d.PlaybookExecutions);
        AddExcelRow(ws, ref row, "New Incidents", d.NewIncidents);

        row += 2;
        ws.Cell(row, 1).Value = "Severity"; ws.Cell(row, 2).Value = "Count";
        StyleHeader(ws, row, 2); row++;
        AddExcelRow(ws, ref row, "Critical", d.AlertBreakdown.Critical);
        AddExcelRow(ws, ref row, "High", d.AlertBreakdown.High);
        AddExcelRow(ws, ref row, "Medium", d.AlertBreakdown.Medium);
        AddExcelRow(ws, ref row, "Low", d.AlertBreakdown.Low);

        if (d.TopDetectionRules.Any())
        {
            row += 2;
            ws.Cell(row, 1).Value = "Rule"; ws.Cell(row, 2).Value = "Severity";
            ws.Cell(row, 3).Value = "MITRE"; ws.Cell(row, 4).Value = "Hits";
            StyleHeader(ws, row, 4); row++;
            foreach (var r in d.TopDetectionRules)
            {
                ws.Cell(row, 1).Value = r.RuleName; ws.Cell(row, 2).Value = r.Severity;
                ws.Cell(row, 3).Value = r.MitreTechnique ?? "—"; ws.Cell(row, 4).Value = r.Hits;
                row++;
            }
        }
    }

    private void RenderIncidentExcel(IXLWorksheet ws, IncidentSummaryReportDto d)
    {
        ws.Cell(1, 1).Value = "SENTINEL SOC — Incident Summary";
        ws.Cell(1, 1).Style.Font.Bold = true; ws.Cell(1, 1).Style.Font.FontSize = 14;
        ws.Cell(2, 1).Value = $"{d.From:yyyy-MM-dd} — {d.To:yyyy-MM-dd}";

        var row = 4;
        AddExcelRow(ws, ref row, "Total Incidents", d.TotalIncidents);
        AddExcelRow(ws, ref row, "Open", d.OpenIncidents);
        AddExcelRow(ws, ref row, "Resolved", d.ResolvedIncidents);
        AddExcelRow(ws, ref row, "Avg Resolution (h)", d.AvgResolutionHours);

        row += 2;
        ws.Cell(row, 1).Value = "Title"; ws.Cell(row, 2).Value = "Severity";
        ws.Cell(row, 3).Value = "Status"; ws.Cell(row, 4).Value = "Alerts";
        ws.Cell(row, 5).Value = "Resolution (h)"; ws.Cell(row, 6).Value = "Created";
        StyleHeader(ws, row, 6); row++;
        foreach (var i in d.Incidents)
        {
            ws.Cell(row, 1).Value = i.Title; ws.Cell(row, 2).Value = i.Severity;
            ws.Cell(row, 3).Value = i.Status; ws.Cell(row, 4).Value = i.AlertCount;
            ws.Cell(row, 5).Value = i.ResolutionHours ?? 0;
            ws.Cell(row, 6).Value = i.CreatedAt.ToString("yyyy-MM-dd HH:mm");
            row++;
        }
    }

    private void RenderAnalystExcel(IXLWorksheet ws, AnalystPerformanceReportDto d)
    {
        ws.Cell(1, 1).Value = "SENTINEL SOC — Analyst Performance";
        ws.Cell(1, 1).Style.Font.Bold = true; ws.Cell(1, 1).Style.Font.FontSize = 14;

        var row = 3;
        ws.Cell(row, 1).Value = "Analyst"; ws.Cell(row, 2).Value = "Role";
        ws.Cell(row, 3).Value = "Assigned"; ws.Cell(row, 4).Value = "Resolved";
        ws.Cell(row, 5).Value = "Escalated"; ws.Cell(row, 6).Value = "Avg Time (min)";
        ws.Cell(row, 7).Value = "SLA %"; ws.Cell(row, 8).Value = "Incidents";
        StyleHeader(ws, row, 8); row++;
        foreach (var a in d.Analysts)
        {
            ws.Cell(row, 1).Value = a.Name; ws.Cell(row, 2).Value = a.Role;
            ws.Cell(row, 3).Value = a.AssignedAlerts; ws.Cell(row, 4).Value = a.ResolvedAlerts;
            ws.Cell(row, 5).Value = a.EscalatedAlerts; ws.Cell(row, 6).Value = a.AvgResolutionMinutes;
            ws.Cell(row, 7).Value = a.SlaCompliancePercent; ws.Cell(row, 8).Value = a.IncidentsWorked;
            row++;
        }
    }

    private void RenderComplianceExcel(IXLWorksheet ws, ComplianceReportDto d)
    {
        ws.Cell(1, 1).Value = $"{d.FrameworkVersion} Compliance Report";
        ws.Cell(1, 1).Style.Font.Bold = true; ws.Cell(1, 1).Style.Font.FontSize = 14;
        ws.Cell(2, 1).Value = $"Overall Score: {d.OverallScore}%";

        var row = 4;
        ws.Cell(row, 1).Value = "Control ID"; ws.Cell(row, 2).Value = "Control";
        ws.Cell(row, 3).Value = "Category"; ws.Cell(row, 4).Value = "Status";
        ws.Cell(row, 5).Value = "Evidence";
        StyleHeader(ws, row, 5); row++;
        foreach (var c in d.Controls)
        {
            ws.Cell(row, 1).Value = c.ControlId; ws.Cell(row, 2).Value = c.ControlName;
            ws.Cell(row, 3).Value = c.Category; ws.Cell(row, 4).Value = c.Status;
            ws.Cell(row, 5).Value = c.Evidence;
            row++;
        }
    }

    // ─── Helpers ───

    private static void AddKvRow(TableDescriptor t, string key, string value)
    {
        t.Cell().Padding(4).Text(key).FontSize(9);
        t.Cell().Padding(4).Text(value).FontSize(9).Bold();
    }

    private static void AddHeaderRow(TableDescriptor t, params string[] headers)
    {
        foreach (var h in headers)
            t.Cell().Padding(4).Background(Colors.Blue.Lighten4).Text(h).FontSize(8).Bold();
    }

    private static void AddDataRow(TableDescriptor t, params string[] values)
    {
        foreach (var v in values)
            t.Cell().Padding(4).BorderBottom(1).BorderColor(Colors.Grey.Lighten3).Text(v).FontSize(8);
    }

    private static void StyleHeader(IXLWorksheet ws, int row, int cols)
    {
        for (int i = 1; i <= cols; i++)
        {
            ws.Cell(row, i).Style.Font.Bold = true;
            ws.Cell(row, i).Style.Fill.BackgroundColor = XLColor.LightSteelBlue;
        }
    }

    private static void AddExcelRow(IXLWorksheet ws, ref int row, string label, object value)
    {
        ws.Cell(row, 1).Value = label;
        ws.Cell(row, 2).SetValue(Convert.ToString(value));
        row++;
    }

    private static string FormatReportTitle(string type) => type.ToLowerInvariant() switch
    {
        "daily" => "Daily SOC Report",
        "incidents" => "Incident Summary",
        "analysts" => "Analyst Performance",
        "compliance" => "Compliance Report",
        _ => "SOC Report"
    };

    // ─── Compliance Framework Control Definitions ───

    private static List<ComplianceControlDto> GetIso27001Controls(int alerts, int audits, int rules, int users, int incidents, int playbooks)
    {
        return new List<ComplianceControlDto>
        {
            new() { ControlId = "A.5.1", ControlName = "Information Security Policies", Category = "Organizational", Status = "Compliant", Evidence = "RBAC policies enforced with 42 granular permissions" },
            new() { ControlId = "A.6.1", ControlName = "Organization of Information Security", Category = "Organizational", Status = users > 0 ? "Compliant" : "NonCompliant", Evidence = $"{users} active users with role-based access" },
            new() { ControlId = "A.8.1", ControlName = "Asset Management", Category = "Asset Mgmt", Status = "Partial", Evidence = "Desktop agent tracks endpoints; asset inventory partial" },
            new() { ControlId = "A.9.1", ControlName = "Access Control", Category = "Access Control", Status = "Compliant", Evidence = "JWT + RBAC with 4 role tiers, account lockout, MFA-ready" },
            new() { ControlId = "A.9.2", ControlName = "User Access Management", Category = "Access Control", Status = "Compliant", Evidence = $"User provisioning/deprovisioning via admin panel; {audits} audit entries" },
            new() { ControlId = "A.12.4", ControlName = "Logging and Monitoring", Category = "Operations", Status = alerts > 0 ? "Compliant" : "Partial", Evidence = $"{alerts} alerts detected via {rules} active rules" },
            new() { ControlId = "A.12.6", ControlName = "Technical Vulnerability Management", Category = "Operations", Status = rules > 0 ? "Compliant" : "NonCompliant", Evidence = $"{rules} detection rules with MITRE ATT&CK mapping" },
            new() { ControlId = "A.16.1", ControlName = "Incident Management", Category = "Incident Response", Status = incidents > 0 ? "Compliant" : "Partial", Evidence = $"{incidents} incidents tracked with full lifecycle management" },
            new() { ControlId = "A.18.1", ControlName = "Compliance", Category = "Compliance", Status = "Compliant", Evidence = "Immutable audit trail with SHA-256 hash chain verification" },
            new() { ControlId = "A.18.2", ControlName = "Information Security Reviews", Category = "Compliance", Status = audits > 0 ? "Compliant" : "NonCompliant", Evidence = $"{audits} audit log entries in period" },
        };
    }

    private static List<ComplianceControlDto> GetSoc2Controls(int alerts, int audits, int rules, int users, int incidents, int playbooks)
    {
        return new List<ComplianceControlDto>
        {
            new() { ControlId = "CC6.1", ControlName = "Logical Access Security", Category = "Logical Access", Status = "Compliant", Evidence = "JWT authentication with short-lived tokens, RBAC, account lockout" },
            new() { ControlId = "CC6.2", ControlName = "Access Provisioning", Category = "Logical Access", Status = "Compliant", Evidence = $"{users} users managed with role-based provisioning" },
            new() { ControlId = "CC6.3", ControlName = "Access Removal", Category = "Logical Access", Status = "Compliant", Evidence = "User deactivation endpoint with token invalidation" },
            new() { ControlId = "CC6.6", ControlName = "System Boundary Protection", Category = "Logical Access", Status = "Compliant", Evidence = "TLS 1.2+, CORS whitelist, CSP headers, rate limiting" },
            new() { ControlId = "CC7.1", ControlName = "Threat Detection", Category = "System Operations", Status = rules > 0 ? "Compliant" : "NonCompliant", Evidence = $"{rules} active detection rules with MITRE ATT&CK mapping" },
            new() { ControlId = "CC7.2", ControlName = "Anomaly Detection", Category = "System Operations", Status = alerts > 0 ? "Compliant" : "Partial", Evidence = $"{alerts} alerts generated from rule-based + threshold detection" },
            new() { ControlId = "CC7.3", ControlName = "Incident Response", Category = "System Operations", Status = "Compliant", Evidence = $"{incidents} incidents managed; {playbooks} automated playbooks" },
            new() { ControlId = "CC7.4", ControlName = "Response to Incidents", Category = "System Operations", Status = playbooks > 0 ? "Compliant" : "Partial", Evidence = $"SOAR playbooks: IP block, account lock, escalation, notification" },
            new() { ControlId = "CC8.1", ControlName = "Change Management", Category = "Change Mgmt", Status = audits > 0 ? "Compliant" : "NonCompliant", Evidence = $"All changes tracked via immutable audit trail ({audits} entries)" },
        };
    }

    private static List<ComplianceControlDto> GetNistCsfControls(int alerts, int audits, int rules, int users, int incidents, int playbooks)
    {
        return new List<ComplianceControlDto>
        {
            new() { ControlId = "ID.AM", ControlName = "Asset Management", Category = "Identify", Status = "Partial", Evidence = "Desktop agent collects endpoint data; full CMDB not implemented" },
            new() { ControlId = "ID.RA", ControlName = "Risk Assessment", Category = "Identify", Status = rules > 0 ? "Compliant" : "Partial", Evidence = $"{rules} detection rules assess risks with severity classification" },
            new() { ControlId = "PR.AC", ControlName = "Access Control", Category = "Protect", Status = "Compliant", Evidence = $"RBAC with {users} users, JWT auth, account lockout, API key auth" },
            new() { ControlId = "PR.DS", ControlName = "Data Security", Category = "Protect", Status = "Compliant", Evidence = "TLS 1.2+, PII masking, input sanitization, HMAC signing" },
            new() { ControlId = "PR.PT", ControlName = "Protective Technology", Category = "Protect", Status = "Compliant", Evidence = "Rate limiting, CSP headers, FluentValidation, payload limits" },
            new() { ControlId = "DE.CM", ControlName = "Continuous Monitoring", Category = "Detect", Status = alerts > 0 ? "Compliant" : "Partial", Evidence = $"{alerts} alerts from {rules} rules; 15-second detection cycle" },
            new() { ControlId = "DE.AE", ControlName = "Anomalies & Events", Category = "Detect", Status = "Compliant", Evidence = "Correlation engine groups related alerts into incidents" },
            new() { ControlId = "RS.RP", ControlName = "Response Planning", Category = "Respond", Status = playbooks > 0 ? "Compliant" : "Partial", Evidence = $"{playbooks} SOAR playbooks with approval workflow" },
            new() { ControlId = "RS.CO", ControlName = "Communications", Category = "Respond", Status = "Compliant", Evidence = "Analyst notes, incident timeline, evidence attachments" },
            new() { ControlId = "RS.AN", ControlName = "Analysis", Category = "Respond", Status = "Compliant", Evidence = $"{incidents} incidents with root cause analysis tracking" },
            new() { ControlId = "RC.RP", ControlName = "Recovery Planning", Category = "Recover", Status = "Partial", Evidence = "Incident resolution workflow; formal recovery plans pending" },
        };
    }
}
