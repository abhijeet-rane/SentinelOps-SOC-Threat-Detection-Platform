using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Collectors;

/// <summary>
/// Monitors authentication events: successful logins (4624) and failed logins (4625).
/// </summary>
public class AuthenticationCollector : ILogCollector
{
    public string Name => "AuthenticationCollector";
    public bool IsEnabled => true;

    private DateTime _lastCollectionTime = DateTime.UtcNow;
    private readonly Guid _endpointId;

    // Windows Security Event IDs for authentication
    private const int EventId_LoginSuccess = 4624;
    private const int EventId_LoginFailure = 4625;

    public AuthenticationCollector(Guid endpointId)
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
                $"*[System[(EventID=4624 or EventID=4625) and TimeCreated[@SystemTime>='{since:yyyy-MM-ddTHH:mm:ss.fffZ}']]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;

            while ((record = reader.ReadEvent()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var isFailure = record.Id == EventId_LoginFailure;

                logs.Add(new LogIngestionDto
                {
                    EndpointId = _endpointId,
                    Source = "Security",
                    EventType = isFailure ? "LoginFailure" : "LoginSuccess",
                    Severity = isFailure ? "High" : "Low",
                    RawData = JsonSerializer.Serialize(new
                    {
                        EventId = record.Id,
                        Description = isFailure ? "Failed logon attempt" : "Successful logon",
                        Provider = record.ProviderName,
                        LogonType = ExtractProperty(record, 8),  // Logon type
                        TargetUser = ExtractProperty(record, 5), // Target username
                        SourceIP = ExtractProperty(record, 18),  // Source network address
                        WorkstationName = ExtractProperty(record, 11)
                    }),
                    SourceIP = ExtractProperty(record, 18),
                    Hostname = Environment.MachineName,
                    Username = ExtractProperty(record, 5),
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
