using SOCPlatform.Core.DTOs;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Dashboard data service interface.
/// </summary>
public interface IDashboardService
{
    Task<DashboardDto> GetDashboardDataAsync();
    Task<List<TopAttackerDto>> GetTopAttackingIPsAsync(int count = 10);
    Task<List<TimeSeriesDataPoint>> GetAlertTrendAsync(int days = 7);
    Task<List<MitreTechniqueDto>> GetMitreTechniquesAsync();
}
