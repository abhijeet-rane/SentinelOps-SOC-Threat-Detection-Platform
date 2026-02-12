using SOCPlatform.Core.DTOs;

namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Incident management service interface.
/// </summary>
public interface IIncidentService
{
    Task<PagedResult<IncidentDto>> GetIncidentsAsync(int page, int pageSize, string? status = null);
    Task<IncidentDto?> GetIncidentByIdAsync(Guid id);
    Task<IncidentDto> CreateIncidentAsync(CreateIncidentDto dto, Guid userId);
    Task<IncidentDto> UpdateIncidentAsync(Guid id, CreateIncidentDto dto, Guid userId);
    Task<IncidentNoteDto> AddNoteAsync(Guid incidentId, AddIncidentNoteDto dto, Guid userId);
}
