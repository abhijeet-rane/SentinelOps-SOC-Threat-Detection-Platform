using System.Net.NetworkInformation;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Collectors;

/// <summary>
/// Collects active network connection metadata using .NET's NetworkInformation APIs.
/// Captures TCP connections with local/remote endpoints and connection state.
/// </summary>
public class NetworkCollector : ILogCollector
{
    public string Name => "NetworkCollector";
    public bool IsEnabled => true;

    private readonly Guid _endpointId;

    public NetworkCollector(Guid endpointId)
    {
        _endpointId = endpointId;
    }

    public Task<List<LogIngestionDto>> CollectAsync(CancellationToken cancellationToken)
    {
        var logs = new List<LogIngestionDto>();

        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var connections = properties.GetActiveTcpConnections();

            // Group connections to avoid flooding — report established and suspicious states
            var interestingConnections = connections
                .Where(c => c.State is TcpState.Established or TcpState.SynSent or TcpState.CloseWait)
                .Take(50)
                .ToList();

            if (interestingConnections.Count > 0)
            {
                logs.Add(new LogIngestionDto
                {
                    EndpointId = _endpointId,
                    Source = "NetworkMonitor",
                    EventType = "ActiveConnections",
                    Severity = "Low",
                    RawData = JsonSerializer.Serialize(new
                    {
                        TotalConnections = connections.Length,
                        Reported = interestingConnections.Count,
                        Connections = interestingConnections.Select(c => new
                        {
                            LocalAddress = c.LocalEndPoint.Address.ToString(),
                            LocalPort = c.LocalEndPoint.Port,
                            RemoteAddress = c.RemoteEndPoint.Address.ToString(),
                            RemotePort = c.RemoteEndPoint.Port,
                            State = c.State.ToString()
                        })
                    }),
                    SourceIP = interestingConnections.FirstOrDefault()?.RemoteEndPoint.Address.ToString(),
                    Hostname = Environment.MachineName,
                    Timestamp = DateTime.UtcNow
                });
            }

            // Flag high number of SYN_SENT as potential port scan
            var synSentCount = connections.Count(c => c.State == TcpState.SynSent);
            if (synSentCount >= 10)
            {
                logs.Add(new LogIngestionDto
                {
                    EndpointId = _endpointId,
                    Source = "NetworkMonitor",
                    EventType = "HighSynSentCount",
                    Severity = "High",
                    RawData = JsonSerializer.Serialize(new
                    {
                        SynSentCount = synSentCount,
                        Note = "Elevated SYN_SENT connections may indicate port scanning activity"
                    }),
                    Hostname = Environment.MachineName,
                    Timestamp = DateTime.UtcNow
                });
            }
        }
        catch (Exception)
        {
            // NetworkInformation may not be available
        }

        return Task.FromResult(logs);
    }
}
