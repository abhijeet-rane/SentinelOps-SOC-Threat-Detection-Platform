using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SOCPlatform.Core.DTOs;
using SOCPlatform.Infrastructure.Services;

namespace SOCPlatform.API.Controllers;

/// <summary>
/// Reporting &amp; Compliance endpoints — daily SOC reports, incident summaries,
/// analyst performance, compliance mapping, with PDF/Excel export.
/// </summary>
[ApiController]
[Asp.Versioning.ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]")]
[Authorize]
public class ReportsController : ControllerBase
{
    private readonly ReportService _reportService;

    public ReportsController(ReportService reportService)
    {
        _reportService = reportService;
    }

    /// <summary>Daily SOC activity report.</summary>
    [HttpGet("daily")]
    public async Task<IActionResult> GetDailyReport([FromQuery] DateTime? from, [FromQuery] DateTime? to)
    {
        var (f, t) = ResolveDates(from, to);
        var report = await _reportService.GenerateDailyReportAsync(f, t);
        return Ok(ApiResponse<DailyReportDto>.Ok(report));
    }

    /// <summary>Incident summary report.</summary>
    [HttpGet("incidents")]
    public async Task<IActionResult> GetIncidentReport([FromQuery] DateTime? from, [FromQuery] DateTime? to)
    {
        var (f, t) = ResolveDates(from, to);
        var report = await _reportService.GenerateIncidentSummaryAsync(f, t);
        return Ok(ApiResponse<IncidentSummaryReportDto>.Ok(report));
    }

    /// <summary>Analyst performance metrics.</summary>
    [HttpGet("analysts")]
    public async Task<IActionResult> GetAnalystReport([FromQuery] DateTime? from, [FromQuery] DateTime? to)
    {
        var (f, t) = ResolveDates(from, to);
        var report = await _reportService.GenerateAnalystPerformanceAsync(f, t);
        return Ok(ApiResponse<AnalystPerformanceReportDto>.Ok(report));
    }

    /// <summary>Compliance mapping report (ISO 27001, SOC 2, NIST CSF).</summary>
    [HttpGet("compliance")]
    public async Task<IActionResult> GetComplianceReport(
        [FromQuery] DateTime? from, [FromQuery] DateTime? to,
        [FromQuery] string framework = "NIST")
    {
        var (f, t) = ResolveDates(from, to);
        var report = await _reportService.GenerateComplianceReportAsync(f, t, framework);
        return Ok(ApiResponse<ComplianceReportDto>.Ok(report));
    }

    /// <summary>Export any report as PDF or Excel.</summary>
    [HttpGet("export")]
    public async Task<IActionResult> ExportReport(
        [FromQuery] string type = "daily",
        [FromQuery] string format = "pdf",
        [FromQuery] DateTime? from = null, [FromQuery] DateTime? to = null,
        [FromQuery] string framework = "NIST")
    {
        var (f, t) = ResolveDates(from, to);

        object reportData = type.ToLowerInvariant() switch
        {
            "daily" => await _reportService.GenerateDailyReportAsync(f, t),
            "incidents" => await _reportService.GenerateIncidentSummaryAsync(f, t),
            "analysts" => await _reportService.GenerateAnalystPerformanceAsync(f, t),
            "compliance" => await _reportService.GenerateComplianceReportAsync(f, t, framework),
            _ => await _reportService.GenerateDailyReportAsync(f, t)
        };

        if (format.Equals("excel", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = _reportService.ExportToExcel(reportData, type);
            return File(bytes,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                $"soc-{type}-report-{f:yyyyMMdd}.xlsx");
        }
        else
        {
            var bytes = _reportService.ExportToPdf(reportData, type);
            return File(bytes, "application/pdf", $"soc-{type}-report-{f:yyyyMMdd}.pdf");
        }
    }

    private static (DateTime from, DateTime to) ResolveDates(DateTime? from, DateTime? to)
    {
        var t = to ?? DateTime.UtcNow;
        var f = from ?? t.AddDays(-30);
        return (f, t);
    }
}
