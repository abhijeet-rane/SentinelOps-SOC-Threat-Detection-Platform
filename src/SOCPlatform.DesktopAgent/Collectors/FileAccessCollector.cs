using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Collectors;

/// <summary>
/// Monitors sensitive file access events (Event ID 4663 – object access attempt).
/// Detects unauthorized access to sensitive files and directories.
/// </summary>
public class FileAccessCollector : ILogCollector
{
    public string Name => "FileAccessCollector";
    public bool IsEnabled => true;

    private DateTime _lastCollectionTime = DateTime.UtcNow;
    private readonly Guid _endpointId;

    private const int EventId_ObjectAccess = 4663;

    public FileAccessCollector(Guid endpointId)
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
                $"*[System[EventID=4663 and TimeCreated[@SystemTime>='{since:yyyy-MM-ddTHH:mm:ss.fffZ}']]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;
            var count = 0;

            while ((record = reader.ReadEvent()) != null && count < 200)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var objectName = ExtractProperty(record, 6);
                var accessMask = ExtractProperty(record, 9);

                logs.Add(new LogIngestionDto
                {
                    EndpointId = _endpointId,
                    Source = "Security",
                    EventType = "FileAccess",
                    Severity = "Medium",
                    RawData = JsonSerializer.Serialize(new
                    {
                        EventId = record.Id,
                        SubjectUser = ExtractProperty(record, 1),
                        SubjectDomain = ExtractProperty(record, 2),
                        ObjectType = ExtractProperty(record, 5),
                        ObjectName = objectName,
                        HandleId = ExtractProperty(record, 7),
                        AccessMask = accessMask,
                        ProcessName = ExtractProperty(record, 11)
                    }),
                    Hostname = Environment.MachineName,
                    Username = ExtractProperty(record, 1),
                    ProcessName = ExtractProperty(record, 11),
                    Timestamp = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow
                });

                count++;
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
