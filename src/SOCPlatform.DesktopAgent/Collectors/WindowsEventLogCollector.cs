using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Collectors;

/// <summary>
/// Collects Windows Event Log entries from Security, System, and Application logs.
/// Reads events since last collection timestamp to avoid duplicates.
/// </summary>
public class WindowsEventLogCollector : ILogCollector
{
    public string Name => "WindowsEventLog";
    public bool IsEnabled => true;

    private DateTime _lastCollectionTime = DateTime.UtcNow;
    private readonly Guid _endpointId;
    private readonly string[] _logNames = ["Security", "System", "Application"];

    public WindowsEventLogCollector(Guid endpointId)
    {
        _endpointId = endpointId;
    }

    public Task<List<LogIngestionDto>> CollectAsync(CancellationToken cancellationToken)
    {
        var logs = new List<LogIngestionDto>();
        var since = _lastCollectionTime;
        _lastCollectionTime = DateTime.UtcNow;

        foreach (var logName in _logNames)
        {
            try
            {
                var query = new EventLogQuery(logName, PathType.LogName,
                    $"*[System[TimeCreated[@SystemTime>='{since:yyyy-MM-ddTHH:mm:ss.fffZ}']]]");

                using var reader = new EventLogReader(query);
                EventRecord? record;
                var count = 0;

                while ((record = reader.ReadEvent()) != null && count < 100)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    logs.Add(new LogIngestionDto
                    {
                        EndpointId = _endpointId,
                        Source = logName,
                        EventType = $"EventId_{record.Id}",
                        Severity = MapSeverity(record.Level),
                        RawData = JsonSerializer.Serialize(new
                        {
                            EventId = record.Id,
                            Level = record.LevelDisplayName,
                            Provider = record.ProviderName,
                            Message = TruncateMessage(record.FormatDescription()),
                            TaskCategory = record.TaskDisplayName,
                            Keywords = record.KeywordsDisplayNames?.ToList()
                        }),
                        Hostname = Environment.MachineName,
                        Username = record.UserId?.Value,
                        ProcessId = record.ProcessId,
                        Timestamp = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow
                    });

                    count++;
                    record.Dispose();
                }
            }
            catch (EventLogNotFoundException)
            {
                // Log not available on this machine (e.g., Security requires admin)
            }
            catch (UnauthorizedAccessException)
            {
                // Insufficient permissions
            }
        }

        return Task.FromResult(logs);
    }

    private static string MapSeverity(byte? level) => level switch
    {
        1 => "Critical",  // Critical
        2 => "High",      // Error
        3 => "Medium",    // Warning
        4 or 5 => "Low",  // Information / Verbose
        _ => "Low"
    };

    private static string? TruncateMessage(string? message) =>
        message?.Length > 2000 ? message[..2000] + "..." : message;
}
