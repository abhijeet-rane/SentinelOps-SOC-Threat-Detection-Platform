using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Collectors;

/// <summary>
/// Monitors privilege escalation events: special privileges assigned (4672), sensitive privilege use (4673).
/// </summary>
public class PrivilegeCollector : ILogCollector
{
    public string Name => "PrivilegeCollector";
    public bool IsEnabled => true;

    private DateTime _lastCollectionTime = DateTime.UtcNow;
    private readonly Guid _endpointId;

    private const int EventId_SpecialPrivileges = 4672;
    private const int EventId_PrivilegeUse = 4673;

    public PrivilegeCollector(Guid endpointId)
    {
        _endpointId = endpointId;
    }

    public Task<List<LogIngestionDto>> CollectAsync(CancellationToken cancellationToken)
    {
        var logs = new List<LogIngestionDto>();
        var since = _lastCollectionTime;
        _lastCollectionTime = DateTime.UtcNow;

        try
        {
            var query = new EventLogQuery("Security", PathType.LogName,
                $"*[System[(EventID=4672 or EventID=4673) and TimeCreated[@SystemTime>='{since:yyyy-MM-ddTHH:mm:ss.fffZ}']]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;

            while ((record = reader.ReadEvent()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();

                logs.Add(new LogIngestionDto
                {
                    EndpointId = _endpointId,
                    Source = "Security",
                    EventType = record.Id == EventId_SpecialPrivileges
                        ? "SpecialPrivilegeAssigned"
                        : "SensitivePrivilegeUse",
                    Severity = "Critical",
                    RawData = JsonSerializer.Serialize(new
                    {
                        EventId = record.Id,
                        Provider = record.ProviderName,
                        SubjectUser = ExtractProperty(record, 1),
                        SubjectDomain = ExtractProperty(record, 2),
                        Privileges = ExtractProperty(record, 4)
                    }),
                    Hostname = Environment.MachineName,
                    Username = ExtractProperty(record, 1),
                    Timestamp = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow
                });

                record.Dispose();
            }
        }
        catch (EventLogNotFoundException) { }
        catch (UnauthorizedAccessException) { }

        return Task.FromResult(logs);
    }

    private static string? ExtractProperty(EventRecord record, int index)
    {
        try
        {
            return record.Properties.Count > index ? record.Properties[index]?.Value?.ToString() : null;
        }
        catch { return null; }
    }
}
