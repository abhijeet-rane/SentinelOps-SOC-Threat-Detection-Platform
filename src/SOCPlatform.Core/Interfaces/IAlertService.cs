using SOCPlatform.Core.DTOs;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Alert management service interface.
/// </summary>
public interface IAlertService
{
    Task<PagedResult<AlertDto>> GetAlertsAsync(int page, int pageSize, AlertStatus? status = null, Severity? severity = null);
    Task<AlertDto?> GetAlertByIdAsync(Guid id);
    Task<AlertDto> UpdateStatusAsync(Guid id, AlertStatusUpdateDto update, Guid userId);
    Task<AlertDto> AssignAlertAsync(Guid id, Guid analystId, Guid assignedBy);
    Task<AlertDto> EscalateAlertAsync(Guid id, Guid userId, string? reason = null);
}
