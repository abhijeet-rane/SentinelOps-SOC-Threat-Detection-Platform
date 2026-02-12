using System.Text.Json;
using SOCPlatform.Core.DTOs;
using SOCPlatform.DesktopAgent.Collectors;

namespace SOCPlatform.DesktopAgent.Services;

/// <summary>
/// Background service that orchestrates all log collectors, batches results,
/// sends to the API, and falls back to SQLite offline buffering when disconnected.
/// </summary>
public class CollectionService
{
    private readonly List<ILogCollector> _collectors;
    private readonly ApiClientService _apiClient;
    private readonly OfflineBufferService _offlineBuffer;
    private readonly Guid _endpointId;
    private readonly TimeSpan _collectionInterval;

    private CancellationTokenSource? _cts;
    private Task? _collectionTask;

    public int TotalLogsCollected { get; private set; }
    public int TotalLogsSent { get; private set; }
    public int BufferedCount => _offlineBuffer.GetBufferedCount();
    public bool IsRunning => _collectionTask is { IsCompleted: false };

    public event Action<string>? StatusChanged;

    public CollectionService(
        ApiClientService apiClient,
        OfflineBufferService offlineBuffer,
        Guid endpointId,
        TimeSpan? collectionInterval = null)
    {
        _apiClient = apiClient;
        _offlineBuffer = offlineBuffer;
        _endpointId = endpointId;
        _collectionInterval = collectionInterval ?? TimeSpan.FromSeconds(30);

        _collectors = new List<ILogCollector>
        {
            new WindowsEventLogCollector(endpointId),
            new AuthenticationCollector(endpointId),
            new PrivilegeCollector(endpointId),
            new FileAccessCollector(endpointId),
            new NetworkCollector(endpointId),
            new USBCollector(endpointId)
        };
    }

    public void Start()
    {
        if (IsRunning) return;

        _cts = new CancellationTokenSource();
        _collectionTask = Task.Run(() => CollectionLoopAsync(_cts.Token));
        StatusChanged?.Invoke("Running");
    }

    public void Stop()
    {
        _cts?.Cancel();
        StatusChanged?.Invoke("Stopped");
    }

    private async Task CollectionLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await CollectAndSendAsync(cancellationToken);
                await FlushOfflineBufferAsync();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Error: {ex.Message}");
            }

            try { await Task.Delay(_collectionInterval, cancellationToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task CollectAndSendAsync(CancellationToken cancellationToken)
    {
        var allLogs = new List<LogIngestionDto>();

        foreach (var collector in _collectors.Where(c => c.IsEnabled))
        {
            try
            {
                var logs = await collector.CollectAsync(cancellationToken);
                allLogs.AddRange(logs);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Collector {collector.Name} error: {ex.Message}");
            }
        }

        if (allLogs.Count == 0) return;

        TotalLogsCollected += allLogs.Count;
        StatusChanged?.Invoke($"Collected {allLogs.Count} logs");

        // Try to send to API
        var batch = new BatchLogIngestionDto
        {
            EndpointId = _endpointId,
            AgentVersion = "1.0.0",
            Logs = allLogs
        };

        var (success, error) = await _apiClient.SendBatchAsync(batch);

        if (success)
        {
            TotalLogsSent += allLogs.Count;
            StatusChanged?.Invoke($"Sent {allLogs.Count} logs to API");
        }
        else
        {
            // Buffer offline
            _offlineBuffer.BufferLogs(allLogs, _endpointId);
            StatusChanged?.Invoke($"Buffered {allLogs.Count} logs offline ({error})");
        }
    }

    private async Task FlushOfflineBufferAsync()
    {
        var buffered = _offlineBuffer.GetBufferedLogs();
        if (buffered.Count == 0) return;

        var successIds = new List<long>();

        foreach (var (id, payload) in buffered)
        {
            try
            {
                var batch = JsonSerializer.Deserialize<BatchLogIngestionDto>(payload);
                if (batch == null) continue;

                var (success, _) = await _apiClient.SendBatchAsync(batch);
                if (success)
                {
                    successIds.Add(id);
                    TotalLogsSent += batch.Logs.Count;
                }
                else
                {
                    break; // Stop trying if API is down
                }
            }
            catch { break; }
        }

        if (successIds.Count > 0)
        {
            _offlineBuffer.RemoveBufferedLogs(successIds);
            StatusChanged?.Invoke($"Flushed {successIds.Count} buffered batches");
        }
    }
}
